
from __future__ import annotations

import asyncio
import json
import os
import re
import ssl
import sys
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urljoin, urlparse

import aiohttp

from core_utils import (
    DEFAULT_CRAWL_DEPTH,
    DEFAULT_MAX_CONCURRENT,
    DEFAULT_TIMEOUT,
    MAX_CRAWL_DEPTH,
    ScanResult,
    crawl,
    fetch,
    make_session,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SENSITIVE_PATHS: list[str] = [
    "/.env", "/.env.local", "/.env.production", "/.env.backup", "/.env.dev",
    "/.git/config", "/.git/HEAD", "/.gitignore",
    "/.htaccess", "/.htpasswd", "/.DS_Store",
    "/backup.zip", "/backup.tar.gz", "/backup.sql",
    "/database.sql", "/db.sql", "/dump.sql",
    "/config.bak", "/config.php.bak", "/web.config",
    "/phpinfo.php", "/info.php", "/test.php",
    "/admin/", "/wp-config.php", "/wp-config.php.bak",
    "/.well-known/security.txt", "/robots.txt", "/sitemap.xml",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/.svn/entries", "/composer.json", "/package.json",
    "/Dockerfile", "/.dockerenv",
    "/server-status", "/server-info",
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/mappings",
    "/swagger.json", "/openapi.json", "/api-docs",
]

HIGH_SEVERITY_PATHS: frozenset[str] = frozenset({
    "/.env", "/.env.local", "/.env.production", "/.env.backup", "/.env.dev",
    "/.git/config", "/.git/HEAD",
    "/backup.zip", "/backup.tar.gz",
    "/backup.sql", "/database.sql", "/db.sql", "/dump.sql",
    "/wp-config.php", "/wp-config.php.bak",
    "/.htpasswd", "/.svn/entries", "/Dockerfile",
    "/actuator/env",
})

SENSITIVE_KEYWORDS: list[str] = [
    "DB_PASSWORD", "DATABASE_PASSWORD", "DB_PASS",
    "API_KEY", "API_SECRET", "SECRET_KEY", "SECRET",
    "ACCESS_KEY", "ACCESS_TOKEN", "PRIVATE_KEY",
    "BEGIN RSA PRIVATE KEY", "BEGIN PRIVATE KEY", "BEGIN EC PRIVATE KEY",
    "PASSWORD=", "PASSWD=", "PWD=", "CLIENT_SECRET",
    "STRIPE_SECRET", "STRIPE_KEY", "AWS_SECRET", "AWS_ACCESS_KEY",
]

REQUIRED_SECURITY_HEADERS: dict[str, dict] = {
    "strict-transport-security": {
        "description": "HTTP Strict Transport Security (HSTS) missing",
        "severity": "High",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "content-security-policy": {
        "description": "Content Security Policy (CSP) missing",
        "severity": "Medium",
        "recommendation": "Define a Content-Security-Policy to restrict resource loading.",
    },
    "x-frame-options": {
        "description": "Clickjacking protection (X-Frame-Options) missing",
        "severity": "Medium",
        "recommendation": "Add: X-Frame-Options: DENY or use CSP frame-ancestors.",
    },
    "x-content-type-options": {
        "description": "MIME-sniffing protection (X-Content-Type-Options) missing",
        "severity": "Low",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
    },
    "referrer-policy": {
        "description": "Referrer-Policy header missing",
        "severity": "Low",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "permissions-policy": {
        "description": "Permissions-Policy header missing",
        "severity": "Low",
        "recommendation": "Add a Permissions-Policy header to restrict browser features.",
    },
}

LEAKY_HEADERS: list[str] = [
    "server", "x-powered-by", "x-aspnet-version",
    "x-aspnetmvc-version", "x-generator", "x-drupal-cache",
]

# ---------------------------------------------------------------------------
# Individual Checks
# ---------------------------------------------------------------------------

def check_security_headers(headers: dict[str, str], url: str, result: ScanResult) -> None:
    headers_lower = {k.lower(): v for k, v in headers.items()}
    csp_value = headers_lower.get("content-security-policy", "")
    has_frame_ancestors = "frame-ancestors" in csp_value.lower()

    for header, meta in REQUIRED_SECURITY_HEADERS.items():
        if header == "x-frame-options" and has_frame_ancestors:
            continue
        if header not in headers_lower:
            result.add(
                f"Missing Header: {header}",
                meta["severity"],
                meta["description"],
                url,
                evidence=meta["recommendation"],
            )

    for leaky in LEAKY_HEADERS:
        if leaky in headers_lower:
            value = headers_lower[leaky]
            result.add(
                "Server Information Leakage",
                "Low",
                f"Header '{leaky}' discloses server technology details.",
                url,
                evidence=f"{leaky}: {value[:80]}",
            )


def check_cookies(headers: dict[str, str], url: str, result: ScanResult) -> None:
    """Parse each Set-Cookie header individually and check security attributes."""
    is_https = urlparse(url).scheme == "https"
    raw_cookies = headers.get("Set-Cookie", "") or headers.get("set-cookie", "")
    if not raw_cookies:
        return

    entries = re.split(r',\s*(?=[A-Za-z_\-]+=)', raw_cookies)
    for entry in entries:
        entry = entry.strip()
        if not entry:
            continue
        directives_lower = entry.lower()
        cookie_name = entry.split(";", 1)[0].split("=", 1)[0].strip()

        if "httponly" not in directives_lower:
            result.add(
                "Cookie Missing HttpOnly",
                "Medium",
                f"Cookie '{cookie_name}' is missing the HttpOnly attribute — readable by JavaScript.",
                url,
                evidence=entry[:100],
            )
        if is_https and "secure" not in directives_lower:
            result.add(
                "Cookie Missing Secure Flag",
                "Medium",
                f"Cookie '{cookie_name}' on HTTPS page is missing the Secure attribute.",
                url,
                evidence=entry[:100],
            )
        if "samesite" not in directives_lower:
            result.add(
                "Cookie Missing SameSite",
                "Low",
                f"Cookie '{cookie_name}' is missing the SameSite attribute (CSRF risk).",
                url,
                evidence=entry[:100],
            )


def check_cors(
    headers: dict[str, str],
    url: str,
    result: ScanResult,
    *,
    request_origin: str = "https://evil.example.com",
) -> None:
    headers_lower = {k.lower(): v for k, v in headers.items()}
    acao = headers_lower.get("access-control-allow-origin", "")
    acac = headers_lower.get("access-control-allow-credentials", "").lower()

    if acao == "*" and acac == "true":
        result.add(
            "CORS Wildcard + Credentials",
            "Critical",
            "ACAO: * with Allow-Credentials: true — any origin can make credentialed cross-origin requests.",
            url,
            evidence=f"ACAO: {acao}, ACAC: {acac}",
        )
    elif acao == "*":
        result.add(
            "CORS Wildcard Origin",
            "Medium",
            "Access-Control-Allow-Origin: * — any origin can read responses.",
            url,
            evidence=f"ACAO: {acao}",
        )
    elif acao == "null":
        result.add(
            "CORS Null Origin Allowed",
            "High",
            "ACAO: null — allows requests from sandboxed iframes and local files.",
            url,
            evidence="ACAO: null",
        )
    elif acao and acao == request_origin:
        result.add(
            "CORS Origin Reflection",
            "High",
            "Server reflects the request Origin header as ACAO — any origin is trusted.",
            url,
            evidence=f"ACAO: {acao}",
        )


async def check_redirect_chain(
    session: aiohttp.ClientSession,
    url: str,
    semaphore: asyncio.Semaphore,
    result: ScanResult,
) -> None:
    resp, _, error = await fetch(session, url, semaphore, allow_redirects=False)
    if error or resp is None:
        return
    loc = resp.headers.get("Location", "")
    if loc and resp.status in (301, 302, 303, 307, 308):
        next_url = urljoin(url, loc)
        parsed_orig = urlparse(url)
        parsed_next = urlparse(next_url)
        if parsed_next.netloc and parsed_next.netloc != parsed_orig.netloc:
            result.add(
                "Potential Open Redirect",
                "Medium",
                f"Redirect from '{url}' leads to external host '{parsed_next.netloc}'.",
                url,
                evidence=f"Location: {loc[:100]}",
            )
        if parsed_orig.scheme == "https" and parsed_next.scheme == "http":
            result.add(
                "HTTPS to HTTP Redirect Downgrade",
                "High",
                "Redirect from HTTPS to HTTP — transport security is downgraded.",
                url,
                evidence=f"Location: {loc[:100]}",
            )


async def check_sensitive_files(
    base_url: str,
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    result: ScanResult,
) -> None:
    base = base_url.rstrip("/")

    async def probe(path: str) -> None:
        full_url = base + path
        resp, body, error = await fetch(session, full_url, semaphore)
        if error or resp is None:
            return
        if resp.status not in (200, 401, 403):
            return
        content_type = resp.headers.get("Content-Type", "")

        if resp.status in (401, 403):
            result.add(
                "Sensitive Path Exists (Protected)",
                "Low",
                f"Sensitive path '{path}' exists but is access-controlled (HTTP {resp.status}).",
                full_url,
                evidence=f"HTTP {resp.status}",
            )
            return

        if not body or len(body) < 10:
            return

        if "text/html" in content_type and path not in ("/admin/", "/phpinfo.php", "/info.php"):
            if "<html" in body[:200].lower() and path.endswith(
                (".env", ".sql", ".bak", ".zip", ".tar.gz", ".json", "config")
            ):
                return

        severity = "High" if path in HIGH_SEVERITY_PATHS else "Medium"
        found_keywords = [kw for kw in SENSITIVE_KEYWORDS if kw.upper() in body.upper()]
        if found_keywords:
            severity = "Critical"

        result.add(
            "Sensitive File Exposed",
            severity,
            f"Sensitive path '{path}' is publicly accessible (HTTP 200, {len(body)} bytes).",
            full_url,
            evidence=f"keywords={found_keywords}" if found_keywords else f"Content-Type: {content_type[:60]}",
        )

    await asyncio.gather(*[probe(p) for p in SENSITIVE_PATHS])


async def check_ssl_tls_async(url: str, result: ScanResult) -> None:
    if not url.startswith("https://"):
        result.add(
            "No HTTPS",
            "High",
            "Target is served over plain HTTP — all traffic is unencrypted.",
            url,
        )
        return

    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or 443

    def _blocking_tls_check() -> tuple:
        import socket
        try:
            ctx = ssl.create_default_context()
            conn = socket.create_connection((hostname, port), timeout=6)
            with ctx.wrap_socket(conn, server_hostname=hostname) as tls:
                cert = tls.getpeercert()
                not_after_str = cert.get("notAfter", "")
                if not_after_str:
                    not_after = datetime.strptime(
                        not_after_str, "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=timezone.utc)
                    days_left = (not_after - datetime.now(timezone.utc)).days
                    if days_left < 0:
                        return ("expired", days_left, not_after_str)
                    elif days_left < 30:
                        return ("expiring_soon", days_left, not_after_str)
                    return ("ok", days_left, not_after_str)
            return ("ok", 9999, "")
        except ssl.SSLCertVerificationError as exc:
            return ("cert_invalid", str(exc))
        except ssl.SSLError as exc:
            return ("ssl_error", str(exc))
        except OSError:
            return ("unreachable",)

    loop = asyncio.get_event_loop()
    tls_result = await loop.run_in_executor(None, _blocking_tls_check)
    if not tls_result:
        return
    status = tls_result[0]
    if status == "expired":
        _, days_left, cert_not_after = tls_result
        result.add("Expired SSL Certificate", "Critical",
                   f"SSL certificate expired {abs(days_left)} day(s) ago.", url, evidence=cert_not_after)
    elif status == "expiring_soon":
        _, days_left, cert_not_after = tls_result
        result.add("SSL Certificate Expiring Soon", "Medium",
                   f"SSL certificate expires in {days_left} day(s).", url, evidence=cert_not_after)
    elif status == "cert_invalid":
        result.add("SSL Certificate Validation Failed", "High",
                   f"SSL certificate is invalid or untrusted: {tls_result[1]}", url)
    elif status == "ssl_error":
        result.add("SSL/TLS Error", "Medium",
                   f"SSL/TLS negotiation error: {tls_result[1]}", url)

# ---------------------------------------------------------------------------
# Top-Level Scanner
# ---------------------------------------------------------------------------

async def scan(
    url: str,
    *,
    timeout: int = DEFAULT_TIMEOUT,
    crawl_depth: int = DEFAULT_CRAWL_DEPTH,
    insecure: bool = False,
    concurrency: int = DEFAULT_MAX_CONCURRENT,
    pre_crawled: Optional[dict[str, Optional[str]]] = None,
) -> dict:
    """
    Run all recon checks against *url* asynchronously.

    Args:
        pre_crawled: Optional pre-crawled {url: body} dict to reuse (skips internal crawl).

    Returns:
        JSON-serializable dict: {target, scanned_urls, findings, errors}
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    result = ScanResult(target=url)
    semaphore = asyncio.Semaphore(concurrency)

    async with make_session(insecure=insecure, timeout=timeout) as session:
        await check_ssl_tls_async(url, result)

        resp, body, error = await fetch(session, url, semaphore)
        if error or resp is None:
            result.errors.append(f"Primary fetch failed: {error}")
        else:
            resp_headers = dict(resp.headers)
            result.scanned_urls.append(str(resp.url))
            check_security_headers(resp_headers, url, result)
            check_cookies(resp_headers, url, result)
            check_cors(resp_headers, url, result)
            await check_redirect_chain(session, url, semaphore, result)

        await check_sensitive_files(url, session, semaphore, result)

        if pre_crawled is not None:
            pages = pre_crawled
        elif crawl_depth > 0:
            pages = await crawl(session, url, semaphore, depth=crawl_depth)
        else:
            pages = {}

        for page_url in pages:
            if page_url not in result.scanned_urls:
                result.scanned_urls.append(page_url)

    return result.to_dict()

# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def main() -> None:
    target = os.environ.get("TARGET_URL", "").strip()
    if not target and len(sys.argv) > 1:
        target = sys.argv[1].strip()
    if not target:
        print(json.dumps({
            "error": "No target URL provided. Set TARGET_URL env var or pass as CLI argument."
        }))
        sys.exit(1)

    crawl_depth = min(
        int(os.environ.get("CRAWL_DEPTH", str(DEFAULT_CRAWL_DEPTH))),
        MAX_CRAWL_DEPTH,
    )
    insecure = os.environ.get("INSECURE", "").lower() in ("1", "true", "yes")
    result = asyncio.run(scan(target, crawl_depth=crawl_depth, insecure=insecure))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
