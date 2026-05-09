
from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import sys
from typing import Optional
from urllib.parse import urlparse

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
# Detection Patterns
# ---------------------------------------------------------------------------

JWT_REGEX = re.compile(
    r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]*\b"
)

INSECURE_STORAGE_RE = re.compile(
    r'(?:localStorage|sessionStorage)\s*\.\s*setItem\s*\(\s*["\']'
    r'(?:token|jwt|auth|access_token|id_token|session|user|role|admin|refresh)["\']',
    re.IGNORECASE,
)

CLIENT_ROLE_CHECK_RE = re.compile(
    r'(?:if\s*\(|&&|\|\|)\s*'
    r'(?:user|currentUser|userData|profile|session|account)\s*[\.\[]\s*'
    r'(?:["\'])?(?:role|isAdmin|is_admin|admin|privilege|permission|scope|level|group)'
    r'(?:["\'])?\s*(?:===?|!==?)',
    re.IGNORECASE,
)

FRONTEND_AUTH_DECISION_RE = re.compile(
    r'(?:if|&&|\|\|)\s*\(?(?:localStorage|sessionStorage|cookie|getCookie|document\.cookie)'
    r'\s*[\.\(][^\)]{0,100}(?:admin|role|isAdmin|auth|permission|superuser)',
    re.IGNORECASE,
)

WEAK_SECRET_RE = re.compile(
    r'(?:jwt[_\-\s]?secret|secret[_\-\s]?key|signing[_\-\s]?key)'
    r'\s*[=:]\s*["\']([^"\'\\]{1,32})["\']',
    re.IGNORECASE,
)

# Bug 4 fix: dummy/placeholder values that should not be flagged as real secrets
_AUTH_DUMMY_VALUES: frozenset[str] = frozenset({
    "your-secret-here", "changeme", "your_secret_here", "replace_me",
    "secret", "mysecret", "example", "placeholder", "insert_here",
    "jwt_secret", "signing_key", "your_signing_key", "xxx", "test",
    "yoursecret", "change_me", "supersecret", "1234567890",
})

# Bug 3 fix: only endpoints that look like API routes should be flagged
_API_PATH_RE = re.compile(
    r'/(?:api|v\d+|graphql|rest|auth|user|account|admin|token|oauth|login|logout)/',
    re.I,
)

INSECURE_COOKIE_JS_RE = re.compile(
    r'document\.cookie\s*\+?=\s*["\'][^"\']*(?:token|auth|session|jwt|access)',
    re.IGNORECASE,
)

SSL_BYPASS_RE = re.compile(
    r'(?:rejectUnauthorized|checkServerIdentity|strictSSL|verify|NODE_TLS_REJECT_UNAUTHORIZED)'
    r'\s*[=:]\s*(?:false|0|"0")',
    re.IGNORECASE,
)

JS_API_ENDPOINT_RE = re.compile(
    r'(?:fetch|axios\.(?:get|post|put|delete|patch)|XMLHttpRequest|http\.(?:get|post))\s*\(\s*'
    r'["\']([^"\']{5,200})["\']',
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# JWT Analysis
# ---------------------------------------------------------------------------

def _b64_decode(data: str) -> Optional[dict]:
    try:
        padding = "=" * (-len(data) % 4)
        raw = base64.urlsafe_b64decode(data + padding).decode("utf-8", errors="replace")
        return json.loads(raw)
    except Exception:
        return None


def analyze_jwt(token: str, source_url: str, result: ScanResult) -> None:
    parts = token.split(".")
    if len(parts) != 3:
        return

    header = _b64_decode(parts[0])
    payload = _b64_decode(parts[1])

    if header is None and payload is None:
        return

    if header is not None:
        alg = str(header.get("alg", "")).strip()
        alg_lower = alg.lower()
        if alg_lower == "none" or alg == "":
            result.add(
                "JWT Algorithm None",
                "Critical",
                "JWT uses alg=none — signature verification is completely disabled.",
                source_url,
                evidence=f"alg={alg!r}",
            )
        elif alg_lower in ("hs256", "hs384", "hs512"):
            result.add(
                "JWT Symmetric Algorithm",
                "Low",
                f"JWT uses symmetric algorithm {alg}. Ensure the secret is strong and never exposed client-side.",
                source_url,
                evidence=f"alg={alg}",
            )
        elif alg_lower not in ("rs256", "rs384", "rs512", "es256", "es384", "es512", "ps256", "ps384", "ps512"):
            result.add(
                "JWT Unknown/Weak Algorithm",
                "Medium",
                f"JWT uses uncommon or potentially weak algorithm: {alg}.",
                source_url,
                evidence=f"alg={alg}",
            )

    if payload is not None:
        if "exp" not in payload:
            result.add(
                "JWT Missing Expiry",
                "High",
                "JWT payload has no 'exp' claim — tokens never expire.",
                source_url,
                evidence="missing exp",
            )
        if "iat" not in payload:
            result.add(
                "JWT Missing iat Claim",
                "Low",
                "JWT payload lacks 'iat' claim, making replay detection harder.",
                source_url,
                evidence="missing iat",
            )
        if "nbf" not in payload and "iat" not in payload:
            result.add(
                "JWT Missing Temporal Claims",
                "Low",
                "JWT payload lacks both 'iat' and 'nbf' claims.",
                source_url,
                evidence="missing iat and nbf",
            )

        sensitive_keys = {"password", "secret", "ssn", "credit_card", "cvv", "pin", "private_key"}
        found_sensitive = sensitive_keys.intersection(k.lower() for k in payload.keys())
        if found_sensitive:
            result.add(
                "Sensitive Data in JWT Payload",
                "High",
                "JWT payload contains sensitive keys. JWTs are readable by anyone with the token.",
                source_url,
                evidence=f"keys: {', '.join(sorted(found_sensitive))}",
            )


def check_jwt_in_content(content: str, source_url: str, result: ScanResult) -> None:
    tokens = JWT_REGEX.findall(content)
    seen: set[str] = set()
    for token in tokens:
        key = ".".join(token.split(".")[:2])
        if key in seen:
            continue
        seen.add(key)
        analyze_jwt(token, source_url, result)

# ---------------------------------------------------------------------------
# Frontend Trust Boundary Checks
# ---------------------------------------------------------------------------

def check_insecure_storage(content: str, source_url: str, result: ScanResult) -> None:
    for match in INSECURE_STORAGE_RE.finditer(content):
        result.add(
            "Insecure Auth Storage",
            "Medium",
            "Auth token stored in localStorage/sessionStorage — accessible to JavaScript (XSS risk).",
            source_url,
            evidence=match.group().strip()[:120],
        )


def check_client_side_role_checks(content: str, source_url: str, result: ScanResult) -> None:
    for match in CLIENT_ROLE_CHECK_RE.finditer(content):
        result.add(
            "Client-Side Privilege Check",
            "High",
            "Access control or role check found in client-side JavaScript. "
            "Authorization must be enforced server-side.",
            source_url,
            evidence=match.group().strip()[:120],
        )
    for match in FRONTEND_AUTH_DECISION_RE.finditer(content):
        result.add(
            "Frontend Auth Decision",
            "High",
            "Security-sensitive decision (admin/auth/role) driven by client-readable storage.",
            source_url,
            evidence=match.group().strip()[:120],
        )


def check_insecure_cookie_js(content: str, source_url: str, result: ScanResult) -> None:
    for match in INSECURE_COOKIE_JS_RE.finditer(content):
        result.add(
            "Insecure Cookie via document.cookie",
            "Medium",
            "Auth/session cookie set via document.cookie — HttpOnly flag cannot be set, readable by JavaScript.",
            source_url,
            evidence=match.group().strip()[:120],
        )


def check_weak_jwt_secret(content: str, source_url: str, result: ScanResult) -> None:
    for match in WEAK_SECRET_RE.finditer(content):
        secret = match.group(1)
        # Bug 4 fix: skip placeholder / example values
        if secret.lower().strip() in _AUTH_DUMMY_VALUES:
            continue
        if len(secret) < 20:
            result.add(
                "Weak Hardcoded JWT Secret",
                "Critical",
                f"Short JWT secret hardcoded in source (length={len(secret)}). "
                "Use a cryptographically random secret of ≥256 bits.",
                source_url,
                evidence=secret[:4] + "****",
            )
        elif len(secret) < 32:
            result.add(
                "Potentially Weak Hardcoded JWT Secret",
                "High",
                f"Hardcoded JWT secret found with moderate length ({len(secret)} chars). "
                "Ensure secrets are not committed to source.",
                source_url,
                evidence=secret[:4] + "****",
            )


def check_ssl_bypass(content: str, source_url: str, result: ScanResult) -> None:
    for match in SSL_BYPASS_RE.finditer(content):
        result.add(
            "SSL/TLS Verification Disabled",
            "High",
            "SSL certificate verification appears disabled in JavaScript/Node.js code.",
            source_url,
            evidence=match.group().strip()[:80],
        )


def extract_api_endpoints(content: str, base_url: str) -> list[str]:
    """
    Bug 3 fix: only flag endpoints whose path looks like an actual API route.
    Paths like /static/logo.png or /favicon.ico appearing in fetch() calls are
    not API endpoints and should not generate findings.
    """
    endpoints: list[str] = []
    base_netloc = urlparse(base_url).netloc
    for match in JS_API_ENDPOINT_RE.finditer(content):
        ep = match.group(1).strip()
        if ep.startswith("/") or urlparse(ep).netloc == base_netloc:
            # Only include paths that look like API routes
            if _API_PATH_RE.search(ep):
                endpoints.append(ep)
    return list(dict.fromkeys(endpoints))


def check_response_headers(headers: dict[str, str], url: str, result: ScanResult) -> None:
    """Check HTTP response headers for auth/session security misconfigurations.

    Bug 1 fix: Cookie security checks (HttpOnly, Secure, SameSite) are intentionally
    NOT performed here — recon_scanner.check_cookies() already owns that logic and
    runs on every crawled URL.  Duplicating those checks produces doubled findings.
    """
    headers_lower = {k.lower(): v for k, v in headers.items()}

    has_xframe = "x-frame-options" in headers_lower
    has_csp = "content-security-policy" in headers_lower
    csp_value = headers_lower.get("content-security-policy", "")
    if not has_xframe and not (has_csp and "frame-ancestors" in csp_value.lower()):
        result.add(
            "Clickjacking Protection Missing",
            "Low",
            "Neither X-Frame-Options nor CSP frame-ancestors directive is set.",
            url,
        )

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
    Run all auth/frontend trust checks against *url* asynchronously.

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
        if pre_crawled is not None:
            pages = pre_crawled
        else:
            pages = await crawl(session, url, semaphore, depth=min(crawl_depth, MAX_CRAWL_DEPTH))

        for page_url, body in pages.items():
            result.scanned_urls.append(page_url)
            if not body:
                continue

            # Bug 5 fix: fetch each page once and reuse the response for header checks.
            # Previously the code fetched again here even though crawl() already fetched it.
            resp, _, error = await fetch(session, page_url, semaphore)
            if error or resp is None:
                result.errors.append(f"{page_url}: {error}")
            else:
                check_response_headers(dict(resp.headers), page_url, result)

            check_jwt_in_content(body, page_url, result)
            check_insecure_storage(body, page_url, result)
            check_client_side_role_checks(body, page_url, result)
            check_insecure_cookie_js(body, page_url, result)
            check_weak_jwt_secret(body, page_url, result)
            check_ssl_bypass(body, page_url, result)

            endpoints = extract_api_endpoints(body, url)
            for ep in endpoints[:20]:
                result.add(
                    "JS API Endpoint Discovered",
                    "Low",
                    "API endpoint referenced in JavaScript — verify it requires proper auth.",
                    page_url,
                    evidence=ep[:120],
                )

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