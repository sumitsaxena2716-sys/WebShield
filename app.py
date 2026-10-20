import os
import json
import time
import socket
import ipaddress
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin, urldefrag

import requests
from flask import Flask, render_template, request, jsonify, send_file, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix

APP_NAME = "WebShield"
DATABASE_PATH = os.environ.get("WEBSHIELD_DB", "webshield.db")
MAX_LINKS = int(os.environ.get("WEBSHIELD_MAX_LINKS", "30"))
REQUEST_TIMEOUT = float(os.environ.get("WEBSHIELD_TIMEOUT", "6"))
MAX_RESPONSE_BYTES = int(os.environ.get("WEBSHIELD_MAX_RESPONSE_BYTES", "1500000"))
USER_AGENT = "WebShield-Audit/1.0 (+authorized defensive security assessment)"

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "dev-only-change-this-before-deployment"),
    MAX_CONTENT_LENGTH=16 * 1024,
    JSON_SORT_KEYS=False,
)
# Only enable ProxyFix when deployed behind a proxy you control.
if os.environ.get("TRUST_PROXY", "0") == "1":
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
logger = logging.getLogger("webshield")

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["120 per hour"],
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
)

SECURITY_HEADERS = {
    "Content-Security-Policy": "Defines allowed content sources and helps reduce XSS impact.",
    "Strict-Transport-Security": "Tells browsers to use HTTPS for future connections (only meaningful over HTTPS).",
    "X-Content-Type-Options": "Prevents MIME-type sniffing.",
    "Referrer-Policy": "Controls how much referrer information browsers send.",
    "Permissions-Policy": "Restricts access to browser features.",
    "X-Frame-Options": "Legacy clickjacking defense; CSP frame-ancestors is preferred.",
}


def init_db():
    import sqlite3

    with sqlite3.connect(DATABASE_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                created_at TEXT NOT NULL,
                score INTEGER NOT NULL,
                findings_json TEXT NOT NULL
            )
        """)
        conn.commit()


init_db()



def normalize_url(raw):
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("Enter a website URL.")

    raw = raw.strip()

    if len(raw) > 2048:
        raise ValueError("URL is too long.")

    # Reject unsupported schemes before adding a default scheme.
    parsed_input = urlparse(raw)
    if parsed_input.scheme and parsed_input.scheme.lower() not in (
        "http", "https"
    ):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    # If no scheme was supplied, default to HTTPS.
    if not parsed_input.scheme:
        raw = "https://" + raw

    parsed = urlparse(raw)

    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not parsed.hostname:
        raise ValueError("The URL must include a valid hostname.")

    if parsed.username or parsed.password:
        raise ValueError(
            "URLs containing embedded credentials are not allowed."
        )

    try:
        port = parsed.port
    except ValueError:
        raise ValueError("Invalid port.") from None

    if port is not None and not (1 <= port <= 65535):
        raise ValueError("Invalid port.")

    hostname = parsed.hostname.lower().rstrip(".")

    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise ValueError("Localhost targets are blocked.")

    return parsed.geturl()


def assert_public_target(url):
    """Block private, loopback, link-local, reserved, and non-global destinations."""
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        raise ValueError("Invalid hostname.")
    try:
        infos = socket.getaddrinfo(
            host,
            parsed.port or (443 if parsed.scheme == "https" else 80),
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror:
        raise ValueError("Hostname could not be resolved.")
    addresses = {info[4][0].split("%")[0] for info in infos}
    if not addresses:
        raise ValueError("Hostname did not resolve to an address.")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise ValueError(
                "Private, local, reserved, or non-public network targets are blocked."
            )
    return True


def safe_request(url, method="GET", stream=False):
    assert_public_target(url)
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.5",
    }
    # Redirects are disabled so each redirect target is validated before another request.
    response = requests.request(
        method,
        url,
        headers=headers,
        timeout=(3, REQUEST_TIMEOUT),
        allow_redirects=False,
        verify=True,
        stream=stream,
    )
    return response


def add_finding(findings, category, title, severity, detail, recommendation):
    findings.append(
        {
            "category": category,
            "title": title,
            "severity": severity,
            "detail": detail,
            "recommendation": recommendation,
        }
    )


def get_response_body(response):
    content = bytearray()
    try:
        for chunk in response.iter_content(chunk_size=16384):
            if not chunk:
                continue
            content.extend(chunk)
            if len(content) > MAX_RESPONSE_BYTES:
                raise ValueError(
                    "Target page exceeded the configured response-size limit."
                )
    finally:
        response.close()
    return bytes(content)


def parse_html(html_bytes):
    from bs4 import BeautifulSoup

    # requests has already applied a bounded response size.
    return BeautifulSoup(html_bytes, "html.parser")


def check_link(url, base_host):
    try:
        response = safe_request(url, method="HEAD")
        status = response.status_code
        response.close()
        if status in (405, 501) or status >= 500:
            response = safe_request(url, method="GET", stream=True)
            status = response.status_code
            response.close()
        return {"url": url, "status": status, "ok": status < 400}
    except Exception as exc:
        return {"url": url, "status": None, "ok": False, "error": str(exc)[:180]}


def run_scan(raw_url, check_links=True):
    target = normalize_url(raw_url)
    assert_public_target(target)
    response = safe_request(target)
    # Do not follow redirects automatically; validate each hop before continuing.
    redirects = []
    for _ in range(4):
        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get("Location")
            response.close()
            if not location:
                break
            next_url = urljoin(response.url, location)
            next_url = normalize_url(next_url)
            assert_public_target(next_url)
            redirects.append(next_url)
            response = safe_request(next_url)
        else:
            break

    final_url = response.url
    status_code = response.status_code
    headers = {k.lower(): v for k, v in response.headers.items()}
    content_type = headers.get("content-type", "")
    body = get_response_body(response)
    findings = []
    links = []
    page_info = {
        "title": "",
        "description": "",
        "favicon": "",
        "viewport": False,
        "canonical": "",
    }

    if urlparse(final_url).scheme != "https":
        add_finding(
            findings,
            "Transport",
            "HTTPS is not enabled",
            "high",
            "The final page URL uses HTTP.",
            "Enable HTTPS with a valid TLS certificate and redirect HTTP to HTTPS.",
        )
    else:
        add_finding(
            findings,
            "Transport",
            "HTTPS is enabled",
            "info",
            "The final page uses HTTPS; the scanner verifies TLS certificates.",
            "Keep TLS configuration current and redirect HTTP traffic to HTTPS.",
        )

    for header, description in SECURITY_HEADERS.items():
        if header.lower() not in headers:
            severity = (
                "medium"
                if header
                in (
                    "Content-Security-Policy",
                    "X-Content-Type-Options",
                    "Referrer-Policy",
                )
                else "low"
            )
            add_finding(
                findings,
                "HTTP Headers",
                f"Missing {header}",
                severity,
                description,
                f"Review and configure the {header} response header for this application.",
            )
        else:
            add_finding(
                findings,
                "HTTP Headers",
                f"{header} present",
                "info",
                f"Found response header: {headers[header.lower()][:240]}",
                "Review the header value to ensure it matches the site's architecture and requirements.",
            )

    if (
        "text/html" in content_type.lower()
        or body.lstrip().startswith(b"<!DOCTYPE html")
        or b"<html" in body[:500].lower()
    ):
        soup = parse_html(body)
        title_tag = soup.find("title")
        title = title_tag.get_text(" ", strip=True) if title_tag else ""
        description_tag = soup.find(
            "meta", attrs={"name": lambda v: v and v.lower() == "description"}
        )
        description = (
            description_tag.get("content", "").strip() if description_tag else ""
        )
        viewport = soup.find(
            "meta", attrs={"name": lambda v: v and v.lower() == "viewport"}
        )
        icon_tag = soup.find(
            "link",
            rel=lambda v: v
            and any(
                "icon" in str(x).lower() for x in (v if isinstance(v, list) else [v])
            ),
        )
        canonical_tag = soup.find(
            "link",
            rel=lambda v: v and "canonical" in (v if isinstance(v, list) else [v]),
        )
        favicon = (
            urljoin(final_url, icon_tag.get("href"))
            if icon_tag and icon_tag.get("href")
            else urljoin(final_url, "/favicon.ico")
        )
        canonical = canonical_tag.get("href", "") if canonical_tag else ""
        page_info = {
            "title": title,
            "description": description,
            "favicon": favicon,
            "viewport": bool(viewport),
            "canonical": canonical,
        }

        if not title:
            add_finding(
                findings,
                "SEO & Quality",
                "Missing page title",
                "low",
                "No meaningful HTML title element was found.",
                "Add a unique, descriptive title for this page.",
            )
        elif len(title) > 70:
            add_finding(
                findings,
                "SEO & Quality",
                "Page title may be too long",
                "low",
                f"Title is {len(title)} characters.",
                "Consider a concise, page-specific title.",
            )
        else:
            add_finding(
                findings,
                "SEO & Quality",
                "Page title found",
                "info",
                title[:180],
                "Ensure the title accurately describes this page.",
            )

        if not description:
            add_finding(
                findings,
                "SEO & Quality",
                "Missing meta description",
                "low",
                "No meta description was found.",
                "Add a concise, unique meta description for search previews.",
            )
        else:
            add_finding(
                findings,
                "SEO & Quality",
                "Meta description found",
                "info",
                description[:240],
                "Keep the description accurate and useful.",
            )

        if not viewport:
            add_finding(
                findings,
                "Mobile",
                "Missing mobile viewport",
                "medium",
                "No viewport meta tag was found.",
                "Add a responsive viewport meta tag and test layouts on small screens.",
            )
        else:
            add_finding(
                findings,
                "Mobile",
                "Viewport meta tag found",
                "info",
                "Responsive viewport metadata is present.",
                "Manually test mobile overflow and touch targets on real devices.",
            )

        if not icon_tag:
            add_finding(
                findings,
                "SEO & Quality",
                "Favicon link not found",
                "low",
                "No explicit icon link was found in the page head.",
                "Add a favicon and an appropriate link rel=icon element.",
            )

        if soup.find("a", href=True):
            raw_links = []
            for anchor in soup.find_all("a", href=True):
                href = anchor.get("href", "").strip()
                if not href or href.startswith(
                    ("#", "mailto:", "tel:", "javascript:", "data:")
                ):
                    continue
                absolute = urldefrag(urljoin(final_url, href))[0]
                parsed_link = urlparse(absolute)
                if (
                    parsed_link.scheme not in ("http", "https")
                    or not parsed_link.hostname
                ):
                    continue
                if absolute not in raw_links:
                    raw_links.append(absolute)
                if len(raw_links) >= MAX_LINKS:
                    break
            if check_links:
                base_host = urlparse(final_url).hostname
                for link in raw_links:
                    # External links are checked too, but each destination must be public.
                    links.append(check_link(link, base_host))
                broken_count = sum(1 for link in links if not link["ok"])
                if broken_count:
                    add_finding(
                        findings,
                        "Links",
                        f"{broken_count} potentially broken link(s)",
                        "medium",
                        f"Checked {len(links)} links; {broken_count} returned an error or could not be reached.",
                        "Review the broken-link list; some servers block automated HEAD/GET requests.",
                    )
                else:
                    add_finding(
                        findings,
                        "Links",
                        "No broken links detected in sample",
                        "info",
                        f"Checked {len(links)} links (limit: {MAX_LINKS}).",
                        "Re-run periodically; this is a bounded sample, not a guarantee that every link works.",
                    )
    else:
        add_finding(
            findings,
            "Content",
            "Target did not return recognizable HTML",
            "info",
            f"Content-Type: {content_type or 'not provided'}",
            "Use an HTML page for page-title, metadata, viewport, and link checks.",
        )

    if status_code >= 400:
        add_finding(
            findings,
            "HTTP",
            f"Target returned HTTP {status_code}",
            "high" if status_code >= 500 else "medium",
            "The target response indicates an HTTP error.",
            "Confirm the page is intended to be publicly reachable and check server logs.",
        )
    elif status_code >= 300:
        add_finding(
            findings,
            "HTTP",
            f"Final response status {status_code}",
            "low",
            "The final response is not a standard 2xx success.",
            "Review redirects and canonical URL behavior.",
        )

    # A simple score based on severity counts; this is an indicative checklist score, not a security guarantee.
    weights = {"critical": 25, "high": 15, "medium": 7, "low": 3}
    deductions = sum(weights.get(f["severity"], 0) for f in findings)
    score = max(0, min(100, 100 - deductions))
    return {
        "target": target,
        "final_url": final_url,
        "status_code": status_code,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "score": score,
        "findings": findings,
        "links": links,
        "page_info": page_info,
        "redirects": redirects,
        "summary": {
            "total": len(findings),
            "high": sum(1 for f in findings if f["severity"] == "high"),
            "medium": sum(1 for f in findings if f["severity"] == "medium"),
            "low": sum(1 for f in findings if f["severity"] == "low"),
            "info": sum(1 for f in findings if f["severity"] == "info"),
            "broken_links": sum(1 for link in links if not link["ok"]),
        },
        "limitations": [
            "This is a defensive, non-invasive configuration review, not a penetration test.",
            "Only a bounded sample of links is checked; some sites block automated requests.",
            "The score is an indicative checklist score and does not represent probability of compromise.",
            "Visual horizontal overflow, button behavior, footer semantics, and accessibility require browser/manual testing.",
        ],
    }


def store_scan(result):
    import sqlite3

    with sqlite3.connect(DATABASE_PATH) as conn:
        cur = conn.execute(
            "INSERT INTO scans (target, created_at, score, findings_json) VALUES (?, ?, ?, ?)",
            (
                result["target"],
                result["scanned_at"],
                result["score"],
                json.dumps(result),
            ),
        )
        conn.commit()
        return cur.lastrowid


@app.after_request
def security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault(
        "Permissions-Policy", "camera=(), microphone=(), geolocation=()"
    )
    # CSP is compatible with the app's local assets and inline JSON data attributes; no inline scripts/styles are used.
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
        "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; "
        "frame-ancestors 'none'; form-action 'self'",
    )
    response.headers.setdefault(
        "Cache-Control",
        "no-store" if request.path.startswith("/api") else "private, max-age=0",
    )
    return response


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/health")
def health():
    return jsonify({"status": "ok", "app": APP_NAME})


@app.post("/api/scan")
@limiter.limit("5 per minute")
def api_scan():
    payload = request.get_json(silent=True) or request.form
    raw_url = payload.get("url", "")
    authorized = str(payload.get("authorized", "")).lower() in (
        "true",
        "1",
        "yes",
        "on",
    )
    check_links = str(payload.get("check_links", "true")).lower() in (
        "true",
        "1",
        "yes",
        "on",
    )
    if not authorized:
        return (
            jsonify(
                {
                    "error": "Confirm that you own the target or have explicit permission to assess it."
                }
            ),
            400,
        )
    try:
        result = run_scan(raw_url, check_links=check_links)
        result["scan_id"] = store_scan(result)
        return jsonify(result)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except requests.exceptions.SSLError:
        return (
            jsonify(
                {
                    "error": "TLS verification failed. Check the target certificate and hostname."
                }
            ),
            400,
        )
    except requests.exceptions.Timeout:
        return (
            jsonify({"error": "The target took too long to respond. Try again later."}),
            504,
        )
    except requests.exceptions.RequestException as exc:
        logger.info("Scan request failed: %s", type(exc).__name__)
        return (
            jsonify(
                {
                    "error": "The target could not be reached safely. Check the URL and try again."
                }
            ),
            502,
        )
    except Exception:
        logger.exception("Unexpected scan failure")
        return (
            jsonify(
                {"error": "The scan could not be completed due to an internal error."}
            ),
            500,
        )


@app.get("/api/history")
@limiter.limit("30 per minute")
def api_history():
    import sqlite3

    with sqlite3.connect(DATABASE_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, target, created_at, score FROM scans ORDER BY id DESC LIMIT 10"
        ).fetchall()
    return jsonify([dict(row) for row in rows])


@app.get("/api/report/<int:scan_id>")
@limiter.limit("30 per minute")
def api_report(scan_id):
    import sqlite3

    with sqlite3.connect(DATABASE_PATH) as conn:
        row = conn.execute(
            "SELECT findings_json FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
    if not row:
        return jsonify({"error": "Report not found."}), 404
    response = jsonify(json.loads(row[0]))
    response.headers["Content-Disposition"] = (
        f'attachment; filename="webshield-report-{scan_id}.json"'
    )
    return response


@app.errorhandler(404)
def not_found(error):
    if request.path.startswith("/api/"):
        return jsonify({"error": "The requested resource was not found."}), 404
    return render_template("404.html"), 404


@app.errorhandler(413)
def too_large(error):
    return jsonify({"error": "Request payload is too large."}), 413


@app.errorhandler(429)
def rate_limited(error):
    if request.path.startswith("/api/"):
        return (
            jsonify({"error": "Too many requests. Please wait before trying again."}),
            429,
        )
    return render_template("429.html"), 429


if __name__ == "__main__":
    # Local development only. Use a production WSGI server for deployment.
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
