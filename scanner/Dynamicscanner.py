"""
Dynamic Vulnerability Scanner — Playwright Edition
====================================================
Detects vulnerabilities in JavaScript-rendered websites using Playwright.

Features:
  ✅ Scans JS-rendered pages (SPA, React, Vue, Angular etc.)
  ✅ Detects secrets in dynamically loaded scripts
  ✅ Inspects localStorage / sessionStorage after JS executes
  ✅ Monitors network requests for sensitive data leaks
  ✅ Simulates user interactions (form fill, button clicks)
  ✅ Detects mixed content, inline event handlers, dangerous sinks
  ✅ Checks for DOM-based XSS sinks
  ✅ Scans console errors / warnings
  ✅ Concurrent multi-check execution via asyncio

Install:
  pip install playwright beautifulsoup4
  playwright install chromium

Usage:
  python dynamic_vuln_scanner.py <target_url>
  python dynamic_vuln_scanner.py http://127.0.0.1:5000
"""

import asyncio
import sys
import re
import time
import json
from dataclasses import dataclass, field
from typing import List, Optional
from playwright.async_api import async_playwright, Page, BrowserContext


# ─────────────────────────────────────────────────────────
#  Data Models
# ─────────────────────────────────────────────────────────

@dataclass
class Vulnerability:
    name: str
    severity: str        # CRITICAL / HIGH / MEDIUM / LOW / INFO
    description: str
    evidence: str = ""
    recommendation: str = ""


@dataclass
class ScanResult:
    target: str
    duration: float = 0.0
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────
#  Secret Patterns (regex)
# ─────────────────────────────────────────────────────────

SECRET_PATTERNS = [
    (r'sk-[A-Za-z0-9]{20,}',                                          "CRITICAL", "OpenAI API Key"),
    (r'AKIA[0-9A-Z]{16}',                                             "CRITICAL", "AWS Access Key ID"),
    (r'AIza[0-9A-Za-z\-_]{35}',                                       "CRITICAL", "Google API Key"),
    (r'ghp_[A-Za-z0-9]{36}',                                          "CRITICAL", "GitHub PAT"),
    (r'sk_live_[0-9a-zA-Z]{24,}',                                     "CRITICAL", "Stripe Live Key"),
    (r'xox[baprs]-[0-9A-Za-z\-]{10,}',                                "HIGH",     "Slack Token"),
    (r'(?i)(password|passwd|secret_key|api_key|apikey)\s*[:=]\s*["\']([^"\']{6,})["\']',
                                                                       "HIGH",     "Hardcoded Credential"),
    (r'ey[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]*',"MEDIUM",  "Raw JWT Token in Source"),
]

XSS_SINKS = [
    "innerHTML", "outerHTML", "document.write", "document.writeln",
    "eval(", "setTimeout(", "setInterval(", "new Function(",
    ".insertAdjacentHTML(", "location.href =", "location.replace(",
]


# ─────────────────────────────────────────────────────────
#  Helper
# ─────────────────────────────────────────────────────────

def redact(value: str, show: int = 5) -> str:
    if len(value) <= show * 2:
        return "*" * len(value)
    return value[:show] + "..." + value[-3:]


# ─────────────────────────────────────────────────────────
#  Check 1 — localStorage / sessionStorage Inspection
# ─────────────────────────────────────────────────────────

async def check_browser_storage(page: Page, url: str) -> List[Vulnerability]:
    """After full JS execution, dump localStorage and sessionStorage and scan for secrets."""
    vulns = []
    try:
        storage = await page.evaluate("""() => {
            const local  = {};
            const session = {};
            for (let i = 0; i < localStorage.length; i++) {
                const k = localStorage.key(i);
                local[k] = localStorage.getItem(k);
            }
            for (let i = 0; i < sessionStorage.length; i++) {
                const k = sessionStorage.key(i);
                session[k] = sessionStorage.getItem(k);
            }
            return { local, session };
        }""")

        def scan_storage(store: dict, store_name: str):
            for key, value in store.items():
                if value is None:
                    continue
                value_str = str(value)
                if re.search(r'ey[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}', value_str):
                    vulns.append(Vulnerability(
                        name=f"JWT Stored in {store_name}",
                        severity="CRITICAL",
                        description=f"A JWT found in {store_name}['{key}'] — accessible to any JS on the page (XSS can steal it).",
                        evidence=f"Key: '{key}'  |  Value (redacted): {redact(value_str, 10)}",
                        recommendation="Store JWTs in HttpOnly cookies, never in Web Storage.",
                    ))
                for sensitive in ["token", "password", "secret", "api_key", "apikey", "auth", "credential"]:
                    if sensitive in key.lower():
                        vulns.append(Vulnerability(
                            name=f"Sensitive Data in {store_name}",
                            severity="HIGH",
                            description=f"{store_name} key '{key}' likely contains sensitive data.",
                            evidence=f"Key: '{key}'  |  Value (redacted): {redact(value_str)}",
                            recommendation=f"Avoid storing sensitive values in {store_name}. Use HttpOnly cookies.",
                        ))
                        break
                for pattern, severity, name in SECRET_PATTERNS:
                    if re.search(pattern, value_str):
                        vulns.append(Vulnerability(
                            name=f"{name} Found in {store_name}",
                            severity=severity,
                            description=f"Pattern for '{name}' matched in {store_name}['{key}'].",
                            evidence=f"Key: '{key}'  |  Value (redacted): {redact(value_str)}",
                            recommendation="Never store real credentials in browser storage. Rotate the exposed key immediately.",
                        ))
                        break

        scan_storage(storage.get("local", {}),   "localStorage")
        scan_storage(storage.get("session", {}), "sessionStorage")

    except Exception as e:
        vulns.append(Vulnerability("Storage Check Error", "INFO", str(e)))
    return vulns


# ─────────────────────────────────────────────────────────
#  Check 2 — JS Source Secret Scanning
# ─────────────────────────────────────────────────────────

async def check_js_secrets(page: Page, url: str) -> List[Vulnerability]:
    """Scan ALL script content (including dynamically injected) for hardcoded secrets."""
    vulns = []
    try:
        scripts = await page.evaluate("""() => {
            return Array.from(document.querySelectorAll('script'))
                        .map(s => s.innerText || s.textContent || '')
                        .filter(s => s.trim().length > 0);
        }""")
        combined = "\n".join(scripts)
        found_names = set()
        for pattern, severity, name in SECRET_PATTERNS:
            matches = re.findall(pattern, combined)
            if matches and name not in found_names:
                found_names.add(name)
                sample = str(matches[0])
                if isinstance(sample, tuple):
                    sample = sample[-1]
                vulns.append(Vulnerability(
                    name=f"{name} in JavaScript Source",
                    severity=severity,
                    description=f"Secret pattern '{name}' found in page JavaScript (including dynamically loaded scripts).",
                    evidence=f"Match (redacted): {redact(sample)}  |  {len(matches)} occurrence(s)",
                    recommendation="Remove all secrets from client-side JS. Use backend API proxies and env vars.",
                ))
    except Exception as e:
        vulns.append(Vulnerability("JS Secret Scan Error", "INFO", str(e)))
    return vulns


# ─────────────────────────────────────────────────────────
#  Check 3 — DOM-based XSS Sink Detection
# ─────────────────────────────────────────────────────────

async def check_dom_xss_sinks(page: Page, url: str) -> List[Vulnerability]:
    """Scan rendered DOM and scripts for dangerous XSS sinks."""
    vulns = []
    try:
        scripts = await page.evaluate("""() => {
            return Array.from(document.querySelectorAll('script'))
                        .map(s => s.innerText || s.textContent || '')
                        .join('\\n');
        }""")
        found_sinks = [s for s in XSS_SINKS if s in scripts]
        if found_sinks:
            vulns.append(Vulnerability(
                name="DOM XSS Dangerous Sinks Detected",
                severity="HIGH",
                description="JavaScript uses dangerous DOM sinks that can lead to XSS if input is not sanitised.",
                evidence=f"Sinks found: {', '.join(found_sinks)}",
                recommendation="Sanitise all user-controlled input before passing to DOM sinks. Use DOMPurify for innerHTML.",
            ))
        inline_handlers = await page.evaluate("""() => {
            const events = ['onclick','onmouseover','onerror','onload','onfocus','onblur',
                            'onkeyup','onkeydown','onsubmit','onchange'];
            let found = [];
            events.forEach(ev => {
                document.querySelectorAll('[' + ev + ']').forEach(el => {
                    found.push(ev + ' on <' + el.tagName.toLowerCase() + '>');
                });
            });
            return [...new Set(found)];
        }""")
        if inline_handlers:
            vulns.append(Vulnerability(
                name="Inline Event Handlers Present",
                severity="MEDIUM",
                description="Inline event handlers (onclick, onerror etc.) bypass CSP and indicate poor separation of concerns.",
                evidence=f"Handlers: {', '.join(inline_handlers[:8])}{'...' if len(inline_handlers) > 8 else ''}",
                recommendation="Move event logic to external JS files. Apply a strict CSP blocking 'unsafe-inline'.",
            ))
    except Exception as e:
        vulns.append(Vulnerability("DOM XSS Check Error", "INFO", str(e)))
    return vulns


# ─────────────────────────────────────────────────────────
#  Check 4 — Network Request Monitoring
# ─────────────────────────────────────────────────────────

async def check_network_leaks(network_log: list, url: str) -> List[Vulnerability]:
    """Analyse captured network requests for secrets in URLs and HTTP leaks."""
    vulns = []
    http_urls = []
    token_in_url = []
    sensitive_params = re.compile(
        r'[?&](token|api_key|apikey|secret|password|passwd|auth|access_token|jwt)=([^&\s]+)',
        re.IGNORECASE
    )
    for req_url in network_log:
        if req_url.startswith("http://") and "localhost" not in req_url and "127." not in req_url:
            http_urls.append(req_url)
        match = sensitive_params.search(req_url)
        if match:
            token_in_url.append((match.group(1), redact(match.group(2)), req_url))
    if http_urls:
        vulns.append(Vulnerability(
            name="Mixed Content / Insecure HTTP Requests",
            severity="HIGH",
            description=f"{len(http_urls)} request(s) made over plain HTTP — data sent unencrypted.",
            evidence=f"Example: {http_urls[0][:100]}",
            recommendation="Ensure all sub-resources and API calls use HTTPS.",
        ))
    for param, value, req_url in token_in_url[:3]:
        vulns.append(Vulnerability(
            name=f"Sensitive Param '{param}' in URL",
            severity="HIGH",
            description=f"Parameter '{param}' sent in URL query string — appears in server logs and browser history.",
            evidence=f"Param: {param}={value}  |  URL: {req_url[:100]}",
            recommendation="Send sensitive values in POST body or Authorization header, never in the URL.",
        ))
    return vulns


# ─────────────────────────────────────────────────────────
#  Check 5 — Console Error / Warning Analysis
# ─────────────────────────────────────────────────────────

async def check_console_messages(console_log: list) -> List[Vulnerability]:
    """Flag security-relevant browser console messages."""
    vulns = []
    security_keywords = [
        ("mixed content",           "HIGH",   "Mixed Content Warning"),
        ("cors",                    "HIGH",   "CORS Error Detected"),
        ("content security policy", "HIGH",   "CSP Violation"),
        ("refused to",              "MEDIUM", "Browser Security Refusal"),
        ("insecure",                "MEDIUM", "Insecure Resource Warning"),
        ("certificate",             "HIGH",   "Certificate Issue"),
        ("deprecated",              "LOW",    "Deprecated API Warning"),
    ]
    matched = {}
    for msg_type, msg_text in console_log:
        text_lower = msg_text.lower()
        for keyword, severity, name in security_keywords:
            if keyword in text_lower and name not in matched:
                matched[name] = Vulnerability(
                    name=f"Console: {name}",
                    severity=severity,
                    description="Browser console reported a security-related message.",
                    evidence=f"[{msg_type.upper()}] {msg_text[:200]}",
                    recommendation="Investigate and resolve browser console security warnings.",
                )
                break
    vulns.extend(matched.values())
    return vulns


# ─────────────────────────────────────────────────────────
#  Check 6 — Form & Input Security
# ─────────────────────────────────────────────────────────

async def check_forms(page: Page, url: str) -> List[Vulnerability]:
    """Inspect all forms for HTTP submission, missing CSRF tokens, password autocomplete."""
    vulns = []
    try:
        forms = await page.evaluate("""() => {
            return Array.from(document.querySelectorAll('form')).map(form => {
                const inputs = Array.from(form.querySelectorAll('input')).map(i => ({
                    type: i.type, name: i.name, autocomplete: i.autocomplete, id: i.id
                }));
                return {
                    action: form.action,
                    method: form.method,
                    inputs: inputs,
                    hasCSRF: form.innerHTML.toLowerCase().includes('csrf') ||
                             form.innerHTML.toLowerCase().includes('_token')
                };
            });
        }""")
        for i, form in enumerate(forms, 1):
            label = f"Form {i} (action: {str(form.get('action','?'))[:60]})"
            action = str(form.get("action", ""))
            if action.startswith("http://"):
                vulns.append(Vulnerability(
                    name="Form Submits Over HTTP",
                    severity="HIGH",
                    description=f"{label} submits data over plain HTTP.",
                    evidence=f"action='{action}'",
                    recommendation="Change form action to HTTPS endpoint.",
                ))
            for inp in form.get("inputs", []):
                if inp.get("type") == "password":
                    ac = inp.get("autocomplete", "")
                    if ac not in ("off", "new-password", "current-password"):
                        vulns.append(Vulnerability(
                            name="Password Field Autocomplete Not Set",
                            severity="LOW",
                            description=f"Password input in {label} missing explicit autocomplete attribute.",
                            evidence=f"Input name='{inp.get('name')}' autocomplete='{ac}'",
                            recommendation="Set autocomplete='current-password' or 'new-password' on password inputs.",
                        ))
            if str(form.get("method", "get")).lower() == "post" and not form.get("hasCSRF"):
                vulns.append(Vulnerability(
                    name="Possible Missing CSRF Token",
                    severity="HIGH",
                    description=f"{label} is a POST form with no visible CSRF token field.",
                    evidence="method=POST, no csrf/token field detected in form HTML",
                    recommendation="Add a CSRF token to all state-changing forms.",
                ))
    except Exception as e:
        vulns.append(Vulnerability("Form Check Error", "INFO", str(e)))
    return vulns


# ─────────────────────────────────────────────────────────
#  Check 7 — Simulate User Interaction (XSS probe)
# ─────────────────────────────────────────────────────────

async def check_interaction_simulation(page: Page, url: str) -> List[Vulnerability]:
    """Fill inputs with an XSS payload and detect alert() triggering or reflection."""
    vulns = []
    xss_payload = "<script>alert('xss')</script>"
    alert_triggered = {"value": False}
    try:
        async def handle_dialog(dialog):
            alert_triggered["value"] = True
            await dialog.dismiss()
        page.on("dialog", handle_dialog)
        inputs = await page.query_selector_all(
            "input[type='text'], input:not([type]), textarea, input[type='search']"
        )
        for inp in inputs[:3]:
            try:
                await inp.fill(xss_payload)
                await inp.press("Enter")
                await page.wait_for_timeout(600)
            except Exception:
                pass
        if alert_triggered["value"]:
            vulns.append(Vulnerability(
                name="Reflected XSS — Alert Triggered",
                severity="CRITICAL",
                description="An alert() was triggered after injecting an XSS payload — site is vulnerable to reflected XSS.",
                evidence=f"Payload: {xss_payload}",
                recommendation="Sanitise and encode all user input before rendering in the DOM. Implement a strict CSP.",
            ))
        else:
            body = await page.content()
            if xss_payload in body or "<script>alert" in body:
                vulns.append(Vulnerability(
                    name="Possible Reflected XSS (Non-Executed)",
                    severity="HIGH",
                    description="XSS payload reflected in HTML but not executed (possibly blocked by browser/CSP).",
                    evidence=f"Payload found in DOM: {xss_payload[:50]}",
                    recommendation="Fix the underlying reflection even if CSP currently blocks execution.",
                ))
    except Exception as e:
        vulns.append(Vulnerability("Interaction Simulation Error", "INFO", str(e)))
    return vulns


# ─────────────────────────────────────────────────────────
#  Check 8 — Page Meta Security
# ─────────────────────────────────────────────────────────

async def check_page_meta(page: Page, url: str) -> List[Vulnerability]:
    """Check meta tags for weak CSP delivery and other page-level security settings."""
    vulns = []
    try:
        meta = await page.evaluate("""() => {
            const csp = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
            return { cspMeta: csp ? csp.content : null };
        }""")
        if meta.get("cspMeta"):
            vulns.append(Vulnerability(
                name="CSP Delivered via Meta Tag (Not Header)",
                severity="LOW",
                description="Content Security Policy is set via <meta> tag, which is weaker than an HTTP response header.",
                evidence=f"CSP meta content: {meta['cspMeta'][:100]}",
                recommendation="Deliver CSP as an HTTP response header for full coverage.",
            ))
    except Exception as e:
        vulns.append(Vulnerability("Meta Check Error", "INFO", str(e)))
    return vulns


# ─────────────────────────────────────────────────────────
#  Orchestrator
# ─────────────────────────────────────────────────────────

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLOR = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[31m",
    "MEDIUM":   "\033[33m",
    "LOW":      "\033[34m",
    "INFO":     "\033[37m",
}
RESET = "\033[0m"
BOLD  = "\033[1m"


async def run_dynamic_scanner(target_url: str) -> ScanResult:
    result = ScanResult(target=target_url)
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url
        result.target = target_url

    network_log: List[str]   = []
    console_log: List[tuple] = []

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-setuid-sandbox"]
        )
        context: BrowserContext = await browser.new_context(
            user_agent="Mozilla/5.0 (compatible; VulnScanner/2.0)",
            ignore_https_errors=True,
            java_script_enabled=True,
        )
        page: Page = await context.new_page()

        page.on("request", lambda req: network_log.append(req.url))
        page.on("console", lambda msg: console_log.append((msg.type, msg.text)))

        start = time.perf_counter()
        try:
            print(f"  🌐  Launching headless Chromium...")
            await page.goto(target_url, wait_until="networkidle", timeout=30_000)
            print(f"  ✅  Page loaded — running {BOLD}8 dynamic checks{RESET} concurrently...\n")
        except Exception as e:
            result.errors.append(f"Page load failed: {e}")
            await browser.close()
            result.duration = time.perf_counter() - start
            return result

        tasks = await asyncio.gather(
            check_browser_storage(page, target_url),
            check_js_secrets(page, target_url),
            check_dom_xss_sinks(page, target_url),
            check_forms(page, target_url),
            check_interaction_simulation(page, target_url),
            check_page_meta(page, target_url),
            return_exceptions=True,
        )

        network_vulns = await check_network_leaks(network_log, target_url)
        console_vulns = await check_console_messages(console_log)

        result.duration = time.perf_counter() - start

        for res in list(tasks) + [network_vulns, console_vulns]:
            if isinstance(res, Exception):
                result.errors.append(str(res))
            else:
                result.vulnerabilities.extend(res)

        await browser.close()

    result.vulnerabilities.sort(key=lambda v: SEVERITY_ORDER.get(v.severity, 99))
    return result


# ─────────────────────────────────────────────────────────
#  Report Printer
# ─────────────────────────────────────────────────────────

def print_report(result: ScanResult) -> None:
    print(f"\n{BOLD}{'='*68}{RESET}")
    print(f"{BOLD}  DYNAMIC VULNERABILITY SCAN REPORT  (Playwright){RESET}")
    print(f"{'='*68}")
    print(f"  Target  : {result.target}")
    print(f"  Duration: {result.duration:.2f}s")
    print(f"  Found   : {len(result.vulnerabilities)} issue(s)")
    print(f"{'='*68}\n")

    if not result.vulnerabilities:
        print("  [OK]  No vulnerabilities detected.\n")
    else:
        counts = {}
        for v in result.vulnerabilities:
            counts[v.severity] = counts.get(v.severity, 0) + 1
        print("  Severity Summary:")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if sev in counts:
                color = SEVERITY_COLOR[sev]
                bar = "█" * min(counts[sev] * 3, 30)
                print(f"    {color}{sev:<10}{RESET}  {bar}  {counts[sev]}")
        print()
        for i, vuln in enumerate(result.vulnerabilities, 1):
            color = SEVERITY_COLOR.get(vuln.severity, "")
            print(f"  {BOLD}[{i:02d}] {color}{vuln.severity}{RESET}{BOLD} -- {vuln.name}{RESET}")
            print(f"       Description   : {vuln.description}")
            if vuln.evidence:
                print(f"       Evidence       : {vuln.evidence}")
            if vuln.recommendation:
                print(f"       Recommendation : {vuln.recommendation}")
            print()

    if result.errors:
        print(f"  Errors during scan:")
        for err in result.errors:
            print(f"     * {err}")
        print()
    print(f"{'='*68}\n")


# ─────────────────────────────────────────────────────────
#  Entry Point
# ─────────────────────────────────────────────────────────

async def main():
    if len(sys.argv) < 2:
        print("Usage: python dynamic_vuln_scanner.py <target_url>")
        print("Example: python dynamic_vuln_scanner.py http://127.0.0.1:5000")
        sys.exit(1)
    target = sys.argv[1]
    print(f"\n  Dynamic Vulnerability Scanner -- Playwright")
    print(f"  Target : {target}")
    print(f"  Engine : Headless Chromium + asyncio concurrent checks\n")
    result = await run_dynamic_scanner(target)
    print_report(result)


if __name__ == "__main__":
    asyncio.run(main())