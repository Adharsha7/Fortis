"""
Async Vulnerability Scanner
============================
Concurrent website vulnerability scanning using aiohttp + asyncio.
Usage: python async_vuln_scanner.py <target_url>
"""

import asyncio
import aiohttp
import time
import sys
import re
from urllib.parse import urlparse, urljoin
from dataclasses import dataclass, field
from typing import List, Optional
from bs4 import BeautifulSoup


# ─────────────────────────────────────────────
#  Data Models
# ─────────────────────────────────────────────

@dataclass
class Vulnerability:
    name: str
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    description: str
    evidence: str = ""
    recommendation: str = ""


@dataclass
class ScanResult:
    target: str
    duration: float = 0.0
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


# ─────────────────────────────────────────────
#  Individual Scan Checks
# ─────────────────────────────────────────────

async def check_security_headers(session: aiohttp.ClientSession, url: str) -> List[Vulnerability]:
    """Check for missing or misconfigured HTTP security headers."""
    vulns = []
    try:
        async with session.get(url, allow_redirects=True) as resp:
            headers = resp.headers

            required = {
                "Strict-Transport-Security": (
                    "HIGH",
                    "Missing HSTS header – site is vulnerable to downgrade attacks.",
                    "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
                ),
                "X-Content-Type-Options": (
                    "MEDIUM",
                    "Missing X-Content-Type-Options – browser may MIME-sniff responses.",
                    "Add: X-Content-Type-Options: nosniff",
                ),
                "X-Frame-Options": (
                    "MEDIUM",
                    "Missing X-Frame-Options – site may be embeddable (clickjacking risk).",
                    "Add: X-Frame-Options: DENY or SAMEORIGIN",
                ),
                "Content-Security-Policy": (
                    "HIGH",
                    "Missing Content-Security-Policy – XSS attacks are easier to execute.",
                    "Define a strict CSP that limits script/style sources.",
                ),
                "Referrer-Policy": (
                    "LOW",
                    "Missing Referrer-Policy – sensitive URL data may leak to third parties.",
                    "Add: Referrer-Policy: strict-origin-when-cross-origin",
                ),
                "Permissions-Policy": (
                    "LOW",
                    "Missing Permissions-Policy – browser features are not restricted.",
                    "Add a Permissions-Policy header limiting camera/mic/geolocation etc.",
                ),
            }

            for header, (severity, desc, rec) in required.items():
                if header not in headers:
                    vulns.append(Vulnerability(
                        name=f"Missing Header: {header}",
                        severity=severity,
                        description=desc,
                        evidence=f"Header '{header}' not present in response.",
                        recommendation=rec,
                    ))

            # Deprecated header check
            if "X-XSS-Protection" in headers:
                val = headers["X-XSS-Protection"]
                if val.strip() != "0":
                    vulns.append(Vulnerability(
                        name="Deprecated X-XSS-Protection Header",
                        severity="LOW",
                        description="X-XSS-Protection is deprecated and may introduce vulnerabilities in older browsers.",
                        evidence=f"Value: {val}",
                        recommendation="Remove the header or set it to '0'. Use CSP instead.",
                    ))

    except Exception as e:
        vulns.append(Vulnerability("Header Check Error", "INFO", str(e)))
    return vulns


async def check_ssl_tls(session: aiohttp.ClientSession, url: str) -> List[Vulnerability]:
    """Check basic SSL/TLS configuration."""
    vulns = []
    parsed = urlparse(url)

    if parsed.scheme != "https":
        vulns.append(Vulnerability(
            name="No HTTPS",
            severity="CRITICAL",
            description="The target does not use HTTPS. All traffic is sent in plain text.",
            evidence=f"Scheme: {parsed.scheme}",
            recommendation="Obtain a TLS certificate (e.g. Let's Encrypt) and redirect HTTP → HTTPS.",
        ))
        return vulns

    # Try connecting over HTTP to check for redirect
    http_url = url.replace("https://", "http://", 1)
    try:
        async with session.get(http_url, allow_redirects=False) as resp:
            if resp.status not in (301, 302, 307, 308):
                vulns.append(Vulnerability(
                    name="No HTTP → HTTPS Redirect",
                    severity="MEDIUM",
                    description="HTTP requests are not redirected to HTTPS.",
                    evidence=f"HTTP status: {resp.status}",
                    recommendation="Configure a permanent (301) redirect from HTTP to HTTPS.",
                ))
    except Exception:
        pass  # HTTP may simply be refused – that's acceptable

    return vulns


async def check_cookies(session: aiohttp.ClientSession, url: str) -> List[Vulnerability]:
    """Check for insecure cookie attributes."""
    vulns = []
    try:
        async with session.get(url, allow_redirects=True) as resp:
            raw_cookies = resp.headers.getall("Set-Cookie", [])
            for cookie in raw_cookies:
                cookie_lower = cookie.lower()
                cookie_name = cookie.split("=")[0].strip()

                if "secure" not in cookie_lower:
                    vulns.append(Vulnerability(
                        name="Cookie Missing Secure Flag",
                        severity="HIGH",
                        description=f"Cookie '{cookie_name}' can be transmitted over HTTP.",
                        evidence=cookie[:120],
                        recommendation="Add the 'Secure' attribute to all cookies.",
                    ))

                if "httponly" not in cookie_lower:
                    vulns.append(Vulnerability(
                        name="Cookie Missing HttpOnly Flag",
                        severity="HIGH",
                        description=f"Cookie '{cookie_name}' is accessible via JavaScript (XSS risk).",
                        evidence=cookie[:120],
                        recommendation="Add the 'HttpOnly' attribute to session/auth cookies.",
                    ))

                if "samesite" not in cookie_lower:
                    vulns.append(Vulnerability(
                        name="Cookie Missing SameSite Attribute",
                        severity="MEDIUM",
                        description=f"Cookie '{cookie_name}' has no SameSite policy (CSRF risk).",
                        evidence=cookie[:120],
                        recommendation="Add 'SameSite=Strict' or 'SameSite=Lax'.",
                    ))
    except Exception as e:
        vulns.append(Vulnerability("Cookie Check Error", "INFO", str(e)))
    return vulns


async def check_information_disclosure(session: aiohttp.ClientSession, url: str) -> List[Vulnerability]:
    """Check for server/technology information leakage."""
    vulns = []
    try:
        async with session.get(url, allow_redirects=True) as resp:
            headers = resp.headers

            if "Server" in headers:
                server_val = headers["Server"]
                # Flag if it reveals version info
                if any(char.isdigit() for char in server_val):
                    vulns.append(Vulnerability(
                        name="Server Version Disclosure",
                        severity="LOW",
                        description="Server header reveals software version, aiding fingerprinting.",
                        evidence=f"Server: {server_val}",
                        recommendation="Configure the server to return a generic or empty Server header.",
                    ))

            for h in ["X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]:
                if h in headers:
                    vulns.append(Vulnerability(
                        name=f"Technology Disclosure via {h}",
                        severity="LOW",
                        description=f"Header '{h}' reveals the backend technology stack.",
                        evidence=f"{h}: {headers[h]}",
                        recommendation=f"Remove or suppress the '{h}' header.",
                    ))
    except Exception as e:
        vulns.append(Vulnerability("Info Disclosure Check Error", "INFO", str(e)))
    return vulns


async def check_sensitive_files(session: aiohttp.ClientSession, url: str) -> List[Vulnerability]:
    """Check for publicly accessible sensitive files/paths."""
    vulns = []
    base = url.rstrip("/")

    paths = [
        ("/.git/HEAD",            "CRITICAL", "Git repository exposed",          "Restrict access to .git/ in server config."),
        ("/.env",                 "CRITICAL", "Environment file exposed",         "Block public access to .env files."),
        ("/wp-config.php.bak",    "CRITICAL", "WordPress config backup exposed",  "Delete backup files or restrict access."),
        ("/config.php.bak",       "CRITICAL", "Config backup exposed",            "Remove backup files from the web root."),
        ("/phpinfo.php",          "HIGH",     "PHP info page exposed",            "Remove phpinfo() files from production."),
        ("/admin",                "MEDIUM",   "Admin panel may be exposed",       "Restrict /admin to internal IPs or require MFA."),
        ("/administrator",        "MEDIUM",   "Admin panel may be exposed",       "Restrict access to the admin interface."),
        ("/robots.txt",           "INFO",     "robots.txt exists",                "Review robots.txt for accidentally disclosed paths."),
        ("/.htaccess",            "MEDIUM",   ".htaccess file accessible",        "Deny direct access to .htaccess files."),
        ("/backup.zip",           "CRITICAL", "Backup archive may be exposed",    "Remove backup files from the web root."),
        ("/server-status",        "HIGH",     "Apache server-status exposed",     "Restrict /server-status to localhost."),
        ("/actuator",             "HIGH",     "Spring Boot actuator exposed",     "Secure or disable actuator endpoints in production."),
        ("/actuator/env",         "CRITICAL", "Spring Boot env actuator exposed", "Disable or authenticate actuator endpoints."),
        ("/console",              "CRITICAL", "Developer console may be exposed", "Disable the web console in production."),
    ]

    async def probe(path, severity, name, rec):
        full_url = base + path
        try:
            async with session.get(full_url, allow_redirects=False) as resp:
                if resp.status == 200:
                    return Vulnerability(
                        name=name,
                        severity=severity,
                        description=f"The path '{path}' returned HTTP 200.",
                        evidence=f"URL: {full_url}  |  Status: {resp.status}",
                        recommendation=rec,
                    )
        except Exception:
            pass
        return None

    tasks = [probe(p, sev, nm, rc) for p, sev, nm, rc in paths]
    results = await asyncio.gather(*tasks)
    vulns = [r for r in results if r is not None]
    return vulns


async def check_cors(session: aiohttp.ClientSession, url: str) -> List[Vulnerability]:
    """Check for overly permissive CORS configuration."""
    vulns = []
    try:
        headers_to_send = {
            "Origin": "https://evil.example.com",
        }
        async with session.get(url, headers=headers_to_send, allow_redirects=True) as resp:
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            if acao == "*":
                vulns.append(Vulnerability(
                    name="Wildcard CORS Policy",
                    severity="MEDIUM",
                    description="ACAO header is set to '*', allowing any origin to read responses.",
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                    recommendation="Restrict ACAO to trusted origins only.",
                ))
            elif acao == "https://evil.example.com":
                sev = "CRITICAL" if acac.lower() == "true" else "HIGH"
                vulns.append(Vulnerability(
                    name="CORS Origin Reflection" + (" with Credentials" if acac.lower() == "true" else ""),
                    severity=sev,
                    description="Server reflects arbitrary Origin header back in ACAO.",
                    evidence=f"ACAO: {acao}  |  ACAC: {acac}",
                    recommendation="Validate Origin against a strict allowlist; never combine reflection with credentials.",
                ))
    except Exception as e:
        vulns.append(Vulnerability("CORS Check Error", "INFO", str(e)))
    return vulns


async def check_clickjacking(session: aiohttp.ClientSession, url: str) -> List[Vulnerability]:
    """Check if the page can be embedded in an iframe (clickjacking)."""
    vulns = []
    try:
        async with session.get(url, allow_redirects=True) as resp:
            xfo = resp.headers.get("X-Frame-Options", "")
            csp = resp.headers.get("Content-Security-Policy", "")
            has_frame_ancestors = "frame-ancestors" in csp.lower()

            if not xfo and not has_frame_ancestors:
                vulns.append(Vulnerability(
                    name="Clickjacking Vulnerability",
                    severity="MEDIUM",
                    description="No X-Frame-Options or CSP frame-ancestors directive found. Page can be embedded.",
                    evidence="Neither X-Frame-Options nor CSP frame-ancestors present.",
                    recommendation="Add 'X-Frame-Options: DENY' or \"Content-Security-Policy: frame-ancestors 'none'\".",
                ))
    except Exception as e:
        vulns.append(Vulnerability("Clickjacking Check Error", "INFO", str(e)))
    return vulns


async def check_open_redirect(session: aiohttp.ClientSession, url: str) -> List[Vulnerability]:
    """Check for open redirect parameters in the URL and common patterns."""
    vulns = []
    redirect_params = ["next", "url", "redirect", "redirect_uri", "return", "returnUrl", "goto", "dest", "destination"]
    payload = "https://evil.example.com"

    for param in redirect_params:
        test_url = f"{url}?{param}={payload}"
        try:
            async with session.get(test_url, allow_redirects=False) as resp:
                if resp.status in (301, 302, 307, 308):
                    location = resp.headers.get("Location", "")
                    if "evil.example.com" in location:
                        vulns.append(Vulnerability(
                            name="Open Redirect",
                            severity="HIGH",
                            description=f"Parameter '{param}' redirects to an arbitrary external URL.",
                            evidence=f"GET {test_url}  →  Location: {location}",
                            recommendation="Validate redirect targets against a strict allowlist of internal paths.",
                        ))
                        break  # One confirmed finding is enough
        except Exception:
            pass
    return vulns


# ─────────────────────────────────────────────
#  Orchestrator
# ─────────────────────────────────────────────

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLOR = {
    "CRITICAL": "\033[91m",   # bright red
    "HIGH":     "\033[31m",   # red
    "MEDIUM":   "\033[33m",   # yellow
    "LOW":      "\033[34m",   # blue
    "INFO":     "\033[37m",   # white
}
RESET = "\033[0m"
BOLD  = "\033[1m"


async def run_scanner(target_url: str) -> ScanResult:
    result = ScanResult(target=target_url)

    # Normalise URL
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url
        result.target = target_url

    connector = aiohttp.TCPConnector(ssl=False, limit=20)
    timeout   = aiohttp.ClientTimeout(total=15)

    async with aiohttp.ClientSession(
        connector=connector,
        timeout=timeout,
        headers={"User-Agent": "VulnScanner/1.0 (security-research)"},
    ) as session:
        start = time.perf_counter()

        # Run ALL checks concurrently
        tasks = [
            check_security_headers(session, target_url),
            check_ssl_tls(session, target_url),
            check_cookies(session, target_url),
            check_information_disclosure(session, target_url),
            check_sensitive_files(session, target_url),
            check_cors(session, target_url),
            check_clickjacking(session, target_url),
            check_open_redirect(session, target_url),
        ]

        all_results = await asyncio.gather(*tasks, return_exceptions=True)

        result.duration = time.perf_counter() - start

        for res in all_results:
            if isinstance(res, Exception):
                result.errors.append(str(res))
            else:
                result.vulnerabilities.extend(res)

    # Sort by severity
    result.vulnerabilities.sort(key=lambda v: SEVERITY_ORDER.get(v.severity, 99))
    return result


# ─────────────────────────────────────────────
#  Report Printer
# ─────────────────────────────────────────────

def print_report(result: ScanResult) -> None:
    print(f"\n{BOLD}{'═'*65}{RESET}")
    print(f"{BOLD}  ASYNC VULNERABILITY SCAN REPORT{RESET}")
    print(f"{'═'*65}")
    print(f"  Target  : {result.target}")
    print(f"  Duration: {result.duration:.2f}s  (concurrent async scan)")
    print(f"  Found   : {len(result.vulnerabilities)} issue(s)")
    print(f"{'═'*65}\n")

    if not result.vulnerabilities:
        print("  ✅  No vulnerabilities detected.\n")
    else:
        counts = {}
        for v in result.vulnerabilities:
            counts[v.severity] = counts.get(v.severity, 0) + 1

        print("  Summary:")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if sev in counts:
                color = SEVERITY_COLOR[sev]
                print(f"    {color}{sev:<10}{RESET} {counts[sev]}")
        print()

        for i, vuln in enumerate(result.vulnerabilities, 1):
            color = SEVERITY_COLOR.get(vuln.severity, "")
            print(f"  {BOLD}[{i:02d}] {color}{vuln.severity}{RESET}{BOLD} – {vuln.name}{RESET}")
            print(f"       Description   : {vuln.description}")
            if vuln.evidence:
                print(f"       Evidence       : {vuln.evidence}")
            if vuln.recommendation:
                print(f"       Recommendation : {vuln.recommendation}")
            print()

    if result.errors:
        print(f"  ⚠  Errors during scan:")
        for err in result.errors:
            print(f"     • {err}")
        print()

    print(f"{'═'*65}\n")


# ─────────────────────────────────────────────
#  Entry Point
# ─────────────────────────────────────────────

async def main():
    if len(sys.argv) < 2:
        print("Usage: python async_vuln_scanner.py <target_url>")
        print("Example: python async_vuln_scanner.py https://example.com")
        sys.exit(1)

    target = sys.argv[1]
    print(f"\n  🔍  Starting async scan on: {target}")
    print(f"  ⚡  All checks run concurrently via asyncio + aiohttp\n")

    result = await run_scanner(target)
    print_report(result)


if __name__ == "__main__":
    asyncio.run(main())