"""
╔══════════════════════════════════════════════════════════════╗
║         FORTIS — Security Header Analyzer                    ║
║  Checks: Presence | Value Quality | Misconfigurations |      ║
║          CSP Strength | HSTS | CORS | Cookie Flags           ║
╚══════════════════════════════════════════════════════════════╝

Usage:
    python security_headers.py --url http://localhost:5000
    python security_headers.py --url https://example.com --verbose
    python security_headers.py --url https://example.com --output report.json
"""

import argparse
import json
import re
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, urljoin

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ══════════════════════════════════════════════
#  Data Structures
# ══════════════════════════════════════════════

@dataclass
class Finding:
    severity: str       # CRITICAL | HIGH | MEDIUM | LOW | INFO | PASS
    category: str
    header: str
    title: str
    description: str
    current_value: str = ""
    recommendation: str = ""
    url: str = ""

@dataclass
class ScanResult:
    target: str
    findings:  list[Finding] = field(default_factory=list)
    errors:    list[str]     = field(default_factory=list)
    raw_headers: dict        = field(default_factory=dict)
    score: int = 0
    max_score: int = 0

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "PASS": 5}
SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[93m",
    "MEDIUM":   "\033[94m",
    "LOW":      "\033[96m",
    "INFO":     "\033[37m",
    "PASS":     "\033[92m",
}
RESET = "\033[0m"
BOLD  = "\033[1m"

# ══════════════════════════════════════════════
#  HTTP Session
# ══════════════════════════════════════════════

def build_session(timeout: int = 10) -> requests.Session:
    s = requests.Session()
    retry = Retry(total=2, backoff_factor=0.3,
                  status_forcelist=[500, 502, 503, 504])
    s.mount("http://",  HTTPAdapter(max_retries=retry))
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.headers.update({"User-Agent": "Mozilla/5.0 (FortisScanner/1.0; SecurityResearch)"})
    s.timeout = timeout
    return s

def safe_get(session, url, verbose=False) -> Optional[requests.Response]:
    try:
        r = session.get(url, timeout=session.timeout,
                        allow_redirects=True, verify=False)
        if verbose:
            print(f"    [{r.status_code}] GET {url}")
        return r
    except Exception as e:
        if verbose:
            print(f"    [ERR] {url} → {e}")
        return None

# ══════════════════════════════════════════════
#  Header Definitions
# ══════════════════════════════════════════════

# Each entry: (header_name, severity_if_missing, points, description)
REQUIRED_HEADERS = [
    ("Content-Security-Policy",   "HIGH",   20, "Prevents XSS by controlling resource loading"),
    ("Strict-Transport-Security", "HIGH",   15, "Forces HTTPS, prevents downgrade attacks"),
    ("X-Frame-Options",           "MEDIUM", 10, "Prevents clickjacking via iframes"),
    ("X-Content-Type-Options",    "MEDIUM", 10, "Prevents MIME-type sniffing attacks"),
    ("Referrer-Policy",           "LOW",     5, "Controls referrer info sent to other sites"),
    ("Permissions-Policy",        "LOW",     5, "Controls browser feature access (camera, mic, etc.)"),
    ("Cross-Origin-Opener-Policy","LOW",     5, "Isolates browsing context from cross-origin docs"),
    ("Cross-Origin-Resource-Policy","LOW",   5, "Controls cross-origin resource loading"),
]

# Headers that should NOT be present (information disclosure)
DANGEROUS_HEADERS = [
    ("Server",           "LOW",    "Reveals web server software and version"),
    ("X-Powered-By",     "LOW",    "Reveals backend technology (PHP, ASP.NET, etc.)"),
    ("X-AspNet-Version", "MEDIUM", "Reveals exact ASP.NET version"),
    ("X-AspNetMvc-Version","MEDIUM","Reveals ASP.NET MVC version"),
    ("X-Generator",      "LOW",    "Reveals CMS or generator (WordPress, Drupal, etc.)"),
    ("X-Drupal-Cache",   "LOW",    "Reveals Drupal CMS usage"),
    ("X-Varnish",        "INFO",   "Reveals Varnish cache usage"),
    ("Via",              "INFO",   "Reveals proxy/CDN chain"),
]

# ══════════════════════════════════════════════
#  Individual Header Analyzers
# ══════════════════════════════════════════════

def analyze_csp(value: str, url: str, result: ScanResult):
    """Deep analysis of Content-Security-Policy value."""
    issues = []
    severity = "PASS"

    # Dangerous directives
    if "unsafe-inline" in value:
        issues.append("'unsafe-inline' allows inline scripts — defeats XSS protection")
        severity = "HIGH"

    if "unsafe-eval" in value:
        issues.append("'unsafe-eval' allows eval() — enables code injection")
        severity = "HIGH"

    if re.search(r"script-src[^;]*\*", value):
        issues.append("Wildcard (*) in script-src allows scripts from any domain")
        severity = "HIGH"

    if "default-src *" in value or "default-src '*'" in value:
        issues.append("Wildcard default-src — CSP provides no protection")
        severity = "CRITICAL"

    # Missing directives
    missing_directives = []
    for directive in ["default-src", "script-src", "object-src", "base-uri"]:
        if directive not in value:
            missing_directives.append(directive)

    if "object-src" not in value and "object-src 'none'" not in value:
        issues.append("Missing object-src — allows Flash/plugin attacks")
        if severity == "PASS":
            severity = "MEDIUM"

    if "base-uri" not in value:
        issues.append("Missing base-uri — allows base tag injection")
        if severity == "PASS":
            severity = "LOW"

    # Check for report-uri / report-to (good practice)
    has_reporting = "report-uri" in value or "report-to" in value

    if issues:
        result.findings.append(Finding(
            severity=severity,
            category="CSP Analysis",
            header="Content-Security-Policy",
            title=f"Weak CSP Configuration ({len(issues)} issue{'s' if len(issues)>1 else ''})",
            description=" | ".join(issues),
            current_value=value[:200],
            recommendation=(
                "Remove 'unsafe-inline' and 'unsafe-eval'. Use nonces or hashes instead. "
                "Add object-src 'none' and base-uri 'self'. Enable CSP reporting."
            ),
            url=url,
        ))
    else:
        result.findings.append(Finding(
            severity="PASS",
            category="CSP Analysis",
            header="Content-Security-Policy",
            title="CSP is properly configured",
            description="No major CSP weaknesses detected." +
                        (" CSP reporting enabled ✓" if has_reporting else ""),
            current_value=value[:200],
            recommendation="Consider adding report-uri for CSP violation monitoring." if not has_reporting else "",
            url=url,
        ))
        result.score += 20


def analyze_hsts(value: str, url: str, result: ScanResult):
    """Analyze Strict-Transport-Security value."""
    issues = []
    severity = "PASS"

    # Extract max-age
    max_age_match = re.search(r'max-age\s*=\s*(\d+)', value)
    if max_age_match:
        max_age = int(max_age_match.group(1))
        if max_age < 31536000:  # less than 1 year
            issues.append(f"max-age={max_age} is too short (recommended: 31536000 = 1 year)")
            severity = "MEDIUM"
        if max_age >= 31536000:
            pass  # good
    else:
        issues.append("No max-age directive found in HSTS header")
        severity = "HIGH"

    if "includeSubDomains" not in value:
        issues.append("Missing includeSubDomains — subdomains not protected")
        if severity == "PASS":
            severity = "LOW"

    if "preload" not in value:
        issues.append("Missing preload directive — not eligible for HSTS preload list")
        if severity == "PASS":
            severity = "INFO"

    if issues:
        result.findings.append(Finding(
            severity=severity,
            category="HSTS Analysis",
            header="Strict-Transport-Security",
            title=f"Weak HSTS Configuration",
            description=" | ".join(issues),
            current_value=value,
            recommendation=(
                "Use: Strict-Transport-Security: max-age=31536000; "
                "includeSubDomains; preload"
            ),
            url=url,
        ))
    else:
        result.findings.append(Finding(
            severity="PASS",
            category="HSTS Analysis",
            header="Strict-Transport-Security",
            title="HSTS properly configured",
            description="max-age ≥ 1 year, includeSubDomains present.",
            current_value=value,
            url=url,
        ))
        result.score += 15


def analyze_xframe(value: str, url: str, result: ScanResult):
    """Analyze X-Frame-Options value."""
    value_upper = value.strip().upper()

    if value_upper in ("DENY", "SAMEORIGIN"):
        result.findings.append(Finding(
            severity="PASS",
            category="Clickjacking Protection",
            header="X-Frame-Options",
            title="X-Frame-Options properly set",
            description=f"Value '{value}' protects against clickjacking.",
            current_value=value,
            url=url,
        ))
        result.score += 10
    elif "ALLOW-FROM" in value_upper:
        result.findings.append(Finding(
            severity="LOW",
            category="Clickjacking Protection",
            header="X-Frame-Options",
            title="X-Frame-Options uses deprecated ALLOW-FROM",
            description="ALLOW-FROM is deprecated and not supported in modern browsers.",
            current_value=value,
            recommendation="Use Content-Security-Policy frame-ancestors directive instead.",
            url=url,
        ))
    else:
        result.findings.append(Finding(
            severity="MEDIUM",
            category="Clickjacking Protection",
            header="X-Frame-Options",
            title="X-Frame-Options has invalid value",
            description=f"Value '{value}' is not a valid X-Frame-Options directive.",
            current_value=value,
            recommendation="Set to DENY or SAMEORIGIN.",
            url=url,
        ))


def analyze_xcto(value: str, url: str, result: ScanResult):
    """Analyze X-Content-Type-Options."""
    if value.strip().lower() == "nosniff":
        result.findings.append(Finding(
            severity="PASS",
            category="MIME Sniffing Protection",
            header="X-Content-Type-Options",
            title="X-Content-Type-Options correctly set",
            description="nosniff prevents MIME-type confusion attacks.",
            current_value=value,
            url=url,
        ))
        result.score += 10
    else:
        result.findings.append(Finding(
            severity="MEDIUM",
            category="MIME Sniffing Protection",
            header="X-Content-Type-Options",
            title="X-Content-Type-Options has invalid value",
            description=f"Value '{value}' is invalid. Only 'nosniff' is valid.",
            current_value=value,
            recommendation="Set to: X-Content-Type-Options: nosniff",
            url=url,
        ))


def analyze_referrer_policy(value: str, url: str, result: ScanResult):
    """Analyze Referrer-Policy value."""
    safe_values = [
        "no-referrer",
        "no-referrer-when-downgrade",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
    ]
    unsafe_values = ["unsafe-url", "origin-when-cross-origin"]

    val = value.strip().lower()
    if val in unsafe_values:
        result.findings.append(Finding(
            severity="MEDIUM",
            category="Referrer Policy",
            header="Referrer-Policy",
            title="Unsafe Referrer-Policy Value",
            description=f"'{value}' leaks full URL to third parties — privacy risk.",
            current_value=value,
            recommendation="Use: strict-origin-when-cross-origin or no-referrer",
            url=url,
        ))
    elif val in safe_values:
        result.findings.append(Finding(
            severity="PASS",
            category="Referrer Policy",
            header="Referrer-Policy",
            title="Referrer-Policy properly configured",
            description=f"'{value}' limits referrer data exposure.",
            current_value=value,
            url=url,
        ))
        result.score += 5
    else:
        result.findings.append(Finding(
            severity="LOW",
            category="Referrer Policy",
            header="Referrer-Policy",
            title="Referrer-Policy has unusual value",
            description=f"'{value}' — verify this is intentional.",
            current_value=value,
            recommendation="Recommended: strict-origin-when-cross-origin",
            url=url,
        ))


def analyze_cors(headers: dict, url: str, result: ScanResult):
    """Analyze CORS headers."""
    acao = headers.get("Access-Control-Allow-Origin", "")
    acac = headers.get("Access-Control-Allow-Credentials", "")

    if acao == "*":
        if acac.lower() == "true":
            result.findings.append(Finding(
                severity="CRITICAL",
                category="CORS Misconfiguration",
                header="Access-Control-Allow-Origin",
                title="CORS Wildcard + Credentials = Critical Misconfiguration",
                description=(
                    "Access-Control-Allow-Origin: * combined with "
                    "Access-Control-Allow-Credentials: true allows any website "
                    "to make authenticated cross-origin requests. Leads to account takeover."
                ),
                current_value=f"ACAO: {acao} | ACAC: {acac}",
                recommendation=(
                    "Never combine wildcard ACAO with credentials=true. "
                    "Explicitly whitelist trusted origins."
                ),
                url=url,
            ))
        else:
            result.findings.append(Finding(
                severity="MEDIUM",
                category="CORS Misconfiguration",
                header="Access-Control-Allow-Origin",
                title="CORS Wildcard Origin",
                description="Any domain can make cross-origin requests to this server.",
                current_value=acao,
                recommendation="Restrict to specific trusted origins.",
                url=url,
            ))
    elif acao and acao != "null":
        result.findings.append(Finding(
            severity="PASS",
            category="CORS Configuration",
            header="Access-Control-Allow-Origin",
            title="CORS restricted to specific origin",
            description=f"CORS allows only: {acao}",
            current_value=acao,
            url=url,
        ))


def analyze_cookies(headers: dict, url: str, result: ScanResult):
    """Analyze Set-Cookie headers for security flags."""
    cookies = headers.get("Set-Cookie", "")
    if not cookies:
        return

    cookie_list = cookies.split("\n") if "\n" in cookies else [cookies]

    for cookie in cookie_list:
        cookie = cookie.strip()
        if not cookie:
            continue

        cookie_name = cookie.split("=")[0].strip()
        issues = []

        if "httponly" not in cookie.lower():
            issues.append("Missing HttpOnly flag — JS can read this cookie (XSS risk)")

        if "secure" not in cookie.lower():
            issues.append("Missing Secure flag — cookie sent over HTTP too")

        samesite_match = re.search(r'samesite\s*=\s*(\w+)', cookie, re.IGNORECASE)
        if not samesite_match:
            issues.append("Missing SameSite flag — CSRF risk")
        elif samesite_match.group(1).lower() == "none":
            if "secure" not in cookie.lower():
                issues.append("SameSite=None requires Secure flag")

        if issues:
            severity = "HIGH" if len(issues) >= 2 else "MEDIUM"
            result.findings.append(Finding(
                severity=severity,
                category="Cookie Security",
                header="Set-Cookie",
                title=f"Insecure Cookie: {cookie_name}",
                description=" | ".join(issues),
                current_value=cookie[:150],
                recommendation=(
                    f"Set cookie with: {cookie_name}=value; "
                    "HttpOnly; Secure; SameSite=Strict"
                ),
                url=url,
            ))
        else:
            result.findings.append(Finding(
                severity="PASS",
                category="Cookie Security",
                header="Set-Cookie",
                title=f"Cookie properly secured: {cookie_name}",
                description="HttpOnly, Secure, and SameSite flags all present.",
                current_value=cookie[:150],
                url=url,
            ))


def analyze_permissions_policy(value: str, url: str, result: ScanResult):
    """Analyze Permissions-Policy header."""
    dangerous_features = ["camera", "microphone", "geolocation",
                          "payment", "usb", "fullscreen"]
    allowed = [f for f in dangerous_features if f"={f}" not in value
               and f"=*" in value]

    if not value.strip():
        result.findings.append(Finding(
            severity="LOW",
            category="Permissions Policy",
            header="Permissions-Policy",
            title="Empty Permissions-Policy",
            description="Header present but empty — no feature restrictions enforced.",
            current_value=value,
            recommendation="Explicitly disable unused features: camera=(), microphone=(), geolocation=()",
            url=url,
        ))
    else:
        result.findings.append(Finding(
            severity="PASS",
            category="Permissions Policy",
            header="Permissions-Policy",
            title="Permissions-Policy header present",
            description="Browser feature access is being controlled.",
            current_value=value[:150],
            url=url,
        ))
        result.score += 5


# ══════════════════════════════════════════════
#  Main Scanner
# ══════════════════════════════════════════════

def scan_headers(session, base_url, result, verbose):
    print(f"\n  {'─'*55}")
    print(f"  🔍  Fetching headers from {base_url}")
    print(f"  {'─'*55}")

    resp = safe_get(session, base_url, verbose)
    if not resp:
        result.errors.append("Could not connect to target")
        return

    headers = {k.lower(): v for k, v in resp.headers.items()}
    result.raw_headers = dict(resp.headers)

    print(f"  ✓  Got response — HTTP {resp.status_code} | "
          f"{len(resp.headers)} headers received\n")

    # ── 1. Check required headers (presence) ──
    print(f"  {'─'*55}")
    print(f"  📋  CHECK 1: Required Security Headers")
    print(f"  {'─'*55}")

    ANALYZER_MAP = {
        "content-security-policy":    analyze_csp,
        "strict-transport-security":  analyze_hsts,
        "x-frame-options":            analyze_xframe,
        "x-content-type-options":     analyze_xcto,
        "referrer-policy":            analyze_referrer_policy,
        "permissions-policy":         analyze_permissions_policy,
    }

    result.max_score += sum(pts for _, _, pts, _ in REQUIRED_HEADERS)

    for header_name, severity, points, desc in REQUIRED_HEADERS:
        header_key = header_name.lower()
        if header_key in headers:
            print(f"  ✅  {header_name}")
            # Deep analysis if we have an analyzer
            if header_key in ANALYZER_MAP:
                ANALYZER_MAP[header_key](headers[header_key], base_url, result)
            else:
                result.score += points
                result.findings.append(Finding(
                    severity="PASS",
                    category="Security Headers",
                    header=header_name,
                    title=f"{header_name} is present",
                    description=desc,
                    current_value=headers[header_key][:150],
                    url=base_url,
                ))
        else:
            print(f"  ❌  {header_name} — MISSING")
            result.findings.append(Finding(
                severity=severity,
                category="Missing Security Headers",
                header=header_name,
                title=f"Missing: {header_name}",
                description=f"{desc}. This header is absent from the response.",
                current_value="NOT SET",
                recommendation=f"Add {header_name} to all HTTP responses.",
                url=base_url,
            ))

    # ── 2. Check dangerous headers (should NOT be present) ──
    print(f"\n  {'─'*55}")
    print(f"  🚨  CHECK 2: Information Disclosure Headers")
    print(f"  {'─'*55}")

    for header_name, severity, desc in DANGEROUS_HEADERS:
        header_key = header_name.lower()
        if header_key in headers:
            print(f"  ⚠️   {header_name}: {headers[header_key]}")
            result.findings.append(Finding(
                severity=severity,
                category="Information Disclosure",
                header=header_name,
                title=f"Server Info Exposed: {header_name}",
                description=f"{desc}. Value: '{headers[header_key]}' — reveals tech stack to attackers.",
                current_value=headers[header_key],
                recommendation=f"Remove or mask the {header_name} header at the reverse proxy.",
                url=base_url,
            ))
        else:
            print(f"  ✅  {header_name} — not exposed")

    # ── 3. CORS Analysis ──
    print(f"\n  {'─'*55}")
    print(f"  🌐  CHECK 3: CORS Configuration")
    print(f"  {'─'*55}")
    analyze_cors(dict(resp.headers), base_url, result)

    # ── 4. Cookie Analysis ──
    print(f"\n  {'─'*55}")
    print(f"  🍪  CHECK 4: Cookie Security Flags")
    print(f"  {'─'*55}")
    analyze_cookies(dict(resp.headers), base_url, result)

    # ── 5. HTTPS check ──
    print(f"\n  {'─'*55}")
    print(f"  🔒  CHECK 5: HTTPS / TLS")
    print(f"  {'─'*55}")
    result.max_score += 10
    if base_url.startswith("https://"):
        print(f"  ✅  Site uses HTTPS")
        result.score += 10
        result.findings.append(Finding(
            severity="PASS",
            category="Transport Security",
            header="HTTPS",
            title="Site served over HTTPS",
            description="Encrypted transport in use.",
            url=base_url,
        ))
    else:
        print(f"  ❌  Site uses HTTP — no encryption")
        result.findings.append(Finding(
            severity="CRITICAL",
            category="Transport Security",
            header="HTTPS",
            title="Site NOT served over HTTPS",
            description="All traffic is unencrypted. Credentials and data exposed in transit.",
            recommendation="Obtain a TLS certificate (free via Let's Encrypt) and redirect HTTP → HTTPS.",
            url=base_url,
        ))

    # ── 6. Check sub-pages too ──
    for path in ["/login", "/api", "/admin"]:
        sub_url = urljoin(base_url, path)
        sub_resp = safe_get(session, sub_url, verbose)
        if sub_resp and sub_resp.status_code == 200:
            sub_headers = {k.lower(): v for k, v in sub_resp.headers.items()}
            # Check if sensitive pages have stricter CSP
            if "content-security-policy" not in sub_headers:
                result.findings.append(Finding(
                    severity="MEDIUM",
                    category="Missing Security Headers",
                    header="Content-Security-Policy",
                    title=f"CSP Missing on Sensitive Page: {path}",
                    description=f"The page {path} does not set a Content-Security-Policy header.",
                    current_value="NOT SET",
                    recommendation="Apply CSP headers on all pages, especially login and API endpoints.",
                    url=sub_url,
                ))
        time.sleep(0.1)


# ══════════════════════════════════════════════
#  Security Score
# ══════════════════════════════════════════════

def get_grade(score: int, max_score: int) -> tuple[str, str]:
    if max_score == 0:
        return "F", "\033[91m"
    pct = (score / max_score) * 100
    if pct >= 90: return "A+", "\033[92m"
    if pct >= 80: return "A",  "\033[92m"
    if pct >= 70: return "B",  "\033[93m"
    if pct >= 60: return "C",  "\033[93m"
    if pct >= 40: return "D",  "\033[91m"
    return "F", "\033[91m"


# ══════════════════════════════════════════════
#  Report
# ══════════════════════════════════════════════

def print_banner():
    print(f"""{BOLD}
╔══════════════════════════════════════════════════════════════╗
║         FORTIS — Security Header Analyzer                    ║
╠══════════════════════════════════════════════════════════════╣
║  ✦ Required header presence & value quality                  ║
║  ✦ CSP deep analysis (unsafe-inline, wildcards)              ║
║  ✦ HSTS strength (max-age, includeSubDomains, preload)       ║
║  ✦ CORS misconfiguration detection                           ║
║  ✦ Cookie security flags (HttpOnly, Secure, SameSite)        ║
║  ✦ Information disclosure headers                            ║
║  ✦ Security grade scoring (A+ to F)                          ║
╚══════════════════════════════════════════════════════════════╝{RESET}""")


def print_report(result: ScanResult):
    from collections import Counter

    sorted_f = sorted(
        [f for f in result.findings if f.severity != "PASS"],
        key=lambda f: SEVERITY_ORDER.get(f.severity, 9)
    )
    passed = [f for f in result.findings if f.severity == "PASS"]

    grade, grade_color = get_grade(result.score, result.max_score)
    pct = int((result.score / result.max_score) * 100) if result.max_score else 0

    print(f"\n{'═'*65}")
    print(f"  {BOLD}SECURITY HEADER REPORT{RESET}")
    print(f"  Target  : {result.target}")
    print(f"  {'─'*40}")
    print(f"  Score   : {BOLD}{result.score}/{result.max_score}{RESET} ({pct}%)")
    print(f"  Grade   : {grade_color}{BOLD}{grade}{RESET}")
    print(f"  Issues  : {len(sorted_f)}  |  Passed: {len(passed)}")
    print(f"{'═'*65}")

    # Severity summary
    if sorted_f:
        counts = Counter(f.severity for f in sorted_f)
        print(f"\n  {BOLD}ISSUES BY SEVERITY{RESET}")
        print(f"  {'─'*45}")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if counts[sev]:
                c   = SEVERITY_COLORS[sev]
                bar = "█" * min(counts[sev] * 3, 35)
                print(f"  {c}{sev:<10}{RESET} {counts[sev]:>2}  {c}{bar}{RESET}")

    # Passed checks
    if passed:
        print(f"\n  {BOLD}✅  PASSING CHECKS{RESET}")
        print(f"  {'─'*45}")
        for f in passed:
            print(f"  {SEVERITY_COLORS['PASS']}✓{RESET}  {f.header} — {f.title}")

    # Issues detail
    if sorted_f:
        print(f"\n  {BOLD}⚠️   ISSUES FOUND{RESET}")
        for i, f in enumerate(sorted_f, 1):
            c = SEVERITY_COLORS.get(f.severity, "")
            print(f"\n  ┌─ Issue #{i}")
            print(f"  │  {BOLD}Severity{RESET}  : {c}{f.severity}{RESET}")
            print(f"  │  {BOLD}Category{RESET}  : {f.category}")
            print(f"  │  {BOLD}Header{RESET}    : {f.header}")
            print(f"  │  {BOLD}Problem{RESET}   : {f.title}")
            print(f"  │  {BOLD}Why Bad{RESET}   : {f.description}")
            if f.current_value and f.current_value != "NOT SET":
                print(f"  │  {BOLD}Current{RESET}   : {f.current_value[:100]}")
            if f.recommendation:
                print(f"  │  {BOLD}Fix{RESET}       : {f.recommendation}")
            print(f"  └{'─'*60}")

    # Raw headers dump
    print(f"\n  {BOLD}📋  ALL RESPONSE HEADERS{RESET}")
    print(f"  {'─'*45}")
    for k, v in result.raw_headers.items():
        print(f"  {BOLD}{k}{RESET}: {v[:100]}")

    if result.errors:
        print(f"\n  {BOLD}ERRORS{RESET}")
        for e in result.errors:
            print(f"  ⚠  {e}")


def save_json(result: ScanResult, path: str):
    data = {
        "target":     result.target,
        "score":      result.score,
        "max_score":  result.max_score,
        "grade":      get_grade(result.score, result.max_score)[0],
        "raw_headers": result.raw_headers,
        "findings": [
            {
                "severity":       f.severity,
                "category":       f.category,
                "header":         f.header,
                "title":          f.title,
                "description":    f.description,
                "current_value":  f.current_value,
                "recommendation": f.recommendation,
                "url":            f.url,
            }
            for f in sorted(result.findings,
                            key=lambda x: SEVERITY_ORDER.get(x.severity, 9))
        ],
        "errors": result.errors,
    }
    with open(path, "w") as fp:
        json.dump(data, fp, indent=2)
    print(f"\n  [+] JSON report saved → {path}")


# ══════════════════════════════════════════════
#  Main
# ══════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="FORTIS — Security Header Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python security_headers.py --url http://localhost:5000
  python security_headers.py --url https://example.com --verbose
  python security_headers.py --url https://example.com --output report.json
        """,
    )
    parser.add_argument("--url",     required=True, help="Target website URL")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--output",  "-o", default="", help="Save JSON report")
    parser.add_argument("--timeout", type=int, default=10)
    args = parser.parse_args()

    target = args.url.strip()
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    parsed   = urlparse(target)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    print_banner()
    print(f"\n  Target  : {BOLD}{base_url}{RESET}")
    print(f"  Timeout : {args.timeout}s")

    session = build_session(args.timeout)
    result  = ScanResult(target=base_url)

    try:
        scan_headers(session, base_url, result, args.verbose)
    except Exception as e:
        result.errors.append(str(e))

    print_report(result)

    if args.output:
        save_json(result, args.output)


if __name__ == "__main__":
    main()