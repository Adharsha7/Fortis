
from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from typing import AsyncGenerator

import aiohttp
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, field_validator
from urllib.parse import urlparse

# ── Step 1: Load .env BEFORE anything reads os.environ ───────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv()
    print("[FORTIS] .env loaded ✓")
except ImportError:
    print("[FORTIS] python-dotenv not installed — reading from real env vars")

# ── Step 2: Read all config from environment (.env values are now in os.environ)
GEMINI_API_KEY: str  = os.environ.get("GEMINI_API_KEY", "")
SCAN_TIMEOUT:   int  = int(os.environ.get("SCAN_TIMEOUT", "120"))
INSECURE:       bool = os.environ.get("INSECURE", "false").lower() in ("1", "true", "yes")
HOST:           str  = os.environ.get("HOST", "0.0.0.0")
PORT:           int  = int(os.environ.get("PORT", "8000"))

# CRAWL_DEPTH is imported after core_utils so we can cap it at MAX_CRAWL_DEPTH
# We'll set it below after core_utils import.

# ── Step 3: Scanner imports ───────────────────────────────────────────────────
import sys
# Make sure Python finds all scanner files in the same directory as main.py
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import recon_scanner
import secret_scanner
import auth_misconfig_scanner
import sqli_checker
import path_traversal_scanner

from core_utils import (
    DEFAULT_MAX_CONCURRENT,
    DEFAULT_TIMEOUT,
    MAX_CRAWL_DEPTH,
    crawl,
    make_session,
)

CRAWL_DEPTH: int = min(int(os.environ.get("CRAWL_DEPTH", "2")), MAX_CRAWL_DEPTH)

# Optional scanners — gracefully disabled if dependencies are missing
try:
    import bola
    BOLA_AVAILABLE = True
except ImportError:
    BOLA_AVAILABLE = False
    print("[FORTIS] bola.py unavailable — install beautifulsoup4")

try:
    import xss_scanner
    XSS_AVAILABLE = True
except ImportError:
    XSS_AVAILABLE = False
    print("[FORTIS] xss_scanner.py unavailable — make sure xss_scanner.py is in the same folder")

# ── Step 4: In-memory scan store ──────────────────────────────────────────────
# Stores all active and completed scans in memory.
# Key = scan_id (UUID), Value = full scan state dict
SCANS: dict[str, dict] = {}

# ── Step 5: Create FastAPI app ────────────────────────────────────────────────
app = FastAPI(
    title="FORTIS Security Scanner",
    description="Async web application vulnerability scanner with AI reporting",
    version="1.0.0",
)

# Allow the frontend (even if opened from file://) to call the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Step 6: Serve frontend from the same directory ────────────────────────────
# This is the "send from directory" setup.
# FastAPI will serve frontend.html and any other static files (css, js, images)
# from the same folder as main.py.
#
# How it works:
#   GET /           → returns frontend.html  (handled by route below)
#   GET /static/... → serves any file in the current directory
#
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Mount the current directory as /static so all files are accessible
app.mount("/static", StaticFiles(directory=BASE_DIR), name="static")


@app.get("/", include_in_schema=False)
async def serve_frontend():
    """Serve frontend.html at the root URL http://localhost:8000/"""
    html_path = os.path.join(BASE_DIR, "frontend.html")
    if not os.path.exists(html_path):
        raise HTTPException(
            status_code=404,
            detail="frontend.html not found. Make sure it is in the same folder as main.py"
        )
    return FileResponse(html_path, media_type="text/html")


# ── Pydantic request model ────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            v = "https://" + v
        parsed = urlparse(v)
        if not parsed.netloc:
            raise ValueError("Invalid URL — must include a valid hostname.")
        return v


class ScanResponse(BaseModel):
    scan_id: str
    message: str


# ── URL reachability check ────────────────────────────────────────────────────

async def check_reachability(url: str, timeout: int = 10) -> tuple[bool, str]:
    """Quick HEAD/GET to verify the target is actually online."""
    try:
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=timeout),
            headers={"User-Agent": "Mozilla/5.0 (FORTIS-Scanner/1.0)"},
        ) as session:
            async with session.get(url, allow_redirects=True):
                return True, ""
    except aiohttp.ClientConnectorError as e:
        return False, f"Connection refused or DNS failed: {e}"
    except asyncio.TimeoutError:
        return False, "Connection timed out"
    except Exception as e:
        return False, str(e)


# ── SSE helper ────────────────────────────────────────────────────────────────

def _sse(event: str, data: dict) -> str:
    """Format a Server-Sent Event string."""
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


# ── Gemini AI report ──────────────────────────────────────────────────────────

async def generate_gemini_report(findings_summary: dict) -> str:
    """
    Send all findings to Gemini and get back a markdown security report.
    API key is read from GEMINI_API_KEY in .env — never from the frontend.

    Uses the new `google-genai` SDK (google.genai).
    Install: pip install google-genai

    Prompt is engineered to produce enterprise-grade, developer-actionable
    remediation guidance with exact code/config fixes for every finding type.
    """
    if not GEMINI_API_KEY:
        return (
            "## AI Report Unavailable\n\n"
            "No Gemini API key configured.\n"
            "Add `GEMINI_API_KEY=your_key_here` to your `.env` file and restart."
        )
    try:
        from google import genai as google_genai
        from google.genai import types as genai_types
    except ImportError:
        return (
            "## AI Report Unavailable\n\n"
            "`google-genai` package not installed.\n\n"
            "Run: `pip uninstall google-generativeai -y && pip install google-genai`"
        )

    # ── Count findings by severity for the prompt context ────────────────────
    sev_counts: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    all_findings_flat: list[dict] = []
    for mod_name, mod_data in findings_summary.items():
        if not isinstance(mod_data, dict):
            continue
        for f in mod_data.get("findings", []):
            sev = f.get("severity", "Low")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            all_findings_flat.append({**f, "module": mod_name})

    total = len(all_findings_flat)

    from datetime import datetime
    scan_date = datetime.utcnow().strftime("%B %d, %Y at %H:%M UTC")

    # ── Serialise findings — cap at 12 000 chars to stay inside context budget ─
    findings_json = json.dumps(findings_summary, indent=2)
    if len(findings_json) > 12_000:
        findings_json = findings_json[:12_000] + "\n... [truncated for brevity] ..."

    # ── SYSTEM INSTRUCTION ────────────────────────────────────────────────────
    system_instruction = """\
You are a Principal Application Security Engineer (AppSec) with 15+ years of \
experience in penetration testing, secure code review, and enterprise security \
architecture. You specialize in producing board-level and developer-level security \
reports that are immediately actionable.

ABSOLUTE RULES — violating any of these is unacceptable:

RULE 1 — ZERO GENERIC ADVICE.
Never write vague phrases such as:
  ✗ "Improve security"           ✗ "Use best practices"
  ✗ "Check your configuration"   ✗ "Sanitize input"
  ✗ "Update your dependencies"   ✗ "Apply patches"
  ✗ "Follow OWASP guidelines"    ✗ "Consult your security team"
Every remediation step MUST be concrete and immediately actionable.

RULE 2 — MANDATORY CODE OR CONFIG FOR EVERY VULNERABILITY CLASS.
For EACH finding type below you MUST include the exact fix shown:

  SQL Injection →
    Exact: Replace string-concatenated queries with parameterized prepared statements.
    Python/psycopg2: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    Python/SQLAlchemy: session.execute(text("SELECT * FROM users WHERE id = :uid"), {"uid": user_id})
    Node/pg: client.query("SELECT * FROM users WHERE id = $1", [userId])
    PHP/PDO: $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?"); $stmt->execute([$id]);
    Show the BEFORE (vulnerable) and AFTER (fixed) version when evidence is available.

  XSS (Cross-Site Scripting) →
    DOM/Reflected: Never use innerHTML, document.write, or eval() with untrusted data.
    Use: element.textContent = userInput  (not innerHTML)
    React: JSX auto-escapes — never use dangerouslySetInnerHTML unless DOMPurify-sanitized.
    Output encoding (server-side): html.escape(value) in Python; he.encode(value) in Node.
    CSP header: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'
    If CSP is missing or weak: provide the exact header value to add to the web server config.

  Path Traversal →
    Exact: Validate that the resolved path starts with the intended base directory.
    Python: safe_base = "/var/app/uploads"; real = os.path.realpath(os.path.join(safe_base, user_input)); assert real.startswith(safe_base + os.sep)
    Node: const resolved = path.resolve(BASE_DIR, userInput); if (!resolved.startsWith(BASE_DIR + path.sep)) throw new Error("Access denied");
    Never pass raw user input to open(), readFile(), include(), or require().

  BOLA / IDOR (Broken Object Level Authorization) →
    Exact: Enforce server-side ownership check on EVERY resource access.
    Python/Flask: if resource.owner_id != current_user.id: abort(403)
    Node/Express: if (resource.userId !== req.user.id) return res.status(403).json({error:"Forbidden"});
    Use opaque UUIDs (not sequential integers) for resource IDs.
    Implement centralized authorization middleware — never rely on the client to pass ownership context.

  Exposed Secrets / API Keys →
    Immediate: Rotate the exposed credential NOW — treat it as fully compromised.
    Store secrets in environment variables: os.environ.get("SECRET_KEY") or process.env.SECRET_KEY
    Use python-dotenv (.env file, never committed): load_dotenv(); key = os.getenv("API_KEY")
    Add .env and *.pem to .gitignore immediately.
    For cloud deployments: use AWS Secrets Manager, GCP Secret Manager, or HashiCorp Vault.
    Scan git history: git log --all --full-history -- .env  and use git-filter-repo to purge.

  JWT / Cookie / Session Security →
    JWT: Always verify signature server-side. Never trust alg: none. Use RS256 or HS256 with a strong secret (32+ bytes).
    Python: jwt.decode(token, SECRET, algorithms=["HS256"])  — never algorithms=["none"]
    Cookie flags: Set-Cookie: session=...; HttpOnly; Secure; SameSite=Strict; Path=/
    Session fixation: regenerate session ID after login: request.session.regenerate() or flask.session.clear() + new token.
    Session timeout: expire idle sessions after 15-30 minutes.

  CORS Misconfiguration →
    Never use: Access-Control-Allow-Origin: *  with  Access-Control-Allow-Credentials: true
    Exact nginx fix: add_header Access-Control-Allow-Origin "https://trusted.example.com" always;
    Express fix: cors({ origin: ["https://trusted.example.com"], credentials: true })
    Validate Origin header against an allowlist — reject or omit the header for unlisted origins.

  Missing / Weak Security Headers →
    Provide the EXACT header string to add to nginx, Apache, or application middleware:
    Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
    X-Frame-Options: DENY
    X-Content-Type-Options: nosniff
    Referrer-Policy: strict-origin-when-cross-origin
    Permissions-Policy: geolocation=(), microphone=(), camera=()
    Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'

  Authentication Misconfiguration →
    Missing rate limiting: implement account lockout after 5 failed attempts; add CAPTCHA after 3.
    Flask-Limiter: @limiter.limit("5 per minute")
    Express: rateLimit({ windowMs: 60_000, max: 5 })
    Default credentials: change ALL default usernames/passwords before deployment; scan with nmap --script=http-default-accounts.
    Password storage: use bcrypt (cost factor ≥ 12), scrypt, or Argon2id — NEVER MD5, SHA1, or unsalted SHA256.

RULE 3 — SHOW BEFORE / AFTER FOR CRITICAL AND HIGH FINDINGS.
When evidence includes a URL, parameter name, or payload, show a realistic
vulnerable snippet and the patched version in fenced code blocks.

RULE 4 — ROADMAP ITEMS MUST BE TICKETS, NOT ESSAYS.
Each roadmap item must read like a Jira ticket:
  Title, Severity, Effort (hours), Owner (Dev/DevOps/Security), and 2-3 line description.

RULE 5 — SECURITY SCORE MUST BE QUANTITATIVE.
Deduct points for each severity tier: Critical −2.5 pts, High −1.5 pts, Medium −0.5 pts.
Cap deductions at 0. Show the deduction arithmetic.
"""

    # ── USER PROMPT ───────────────────────────────────────────────────────────
    prompt = f"""
TARGET URL    : {findings_summary.get("target", "Unknown")}
SCAN DATE     : {scan_date}
TOTAL FINDINGS: {total}
  Critical : {sev_counts.get("Critical", 0)}
  High     : {sev_counts.get("High", 0)}
  Medium   : {sev_counts.get("Medium", 0)}
  Low      : {sev_counts.get("Low", 0)}
  Info     : {sev_counts.get("Info", 0)}

SCAN RESULTS (JSON):
{findings_json}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
REPORT REQUIREMENTS — follow this structure EXACTLY, in this order.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

## Executive Summary

Write 3 focused paragraphs:
1. Overall security posture and scan scope (what was scanned, when, how many URLs crawled).
2. Key risk areas found — name the specific vulnerability classes detected (SQLi, XSS, etc.).
3. Urgency statement: be direct about whether this application is safe for production,
   citing the exact count of Critical and High findings.

## Risk Overview

Markdown table:
| Severity | Count | Business Risk |
|----------|-------|---------------|
Fill in all five severity rows. In the Business Risk column, write a single concrete
sentence about what that severity tier means operationally (data breach, account takeover,
information disclosure, etc.).

## Critical and High Severity Findings

For EVERY Critical or High finding in the JSON, write a block in this exact format:

### [SEVERITY] — [Finding Name]
**Affected Endpoint:** `<url or parameter from evidence>`
**Vulnerability Class:** <OWASP category, e.g. A03:2021 – Injection>
**Description:** 2–3 sentences explaining exactly what was detected and why it is exploitable.
**Business Impact:** 1–2 sentences describing real-world attacker capability (data exfiltration, RCE, privilege escalation, etc.).
**Evidence Captured:**
```
<paste the raw evidence string from the scan JSON>
```
**Remediation (Exact Fix Required):**
Step 1 — <specific action with no ambiguity>
Step 2 — <code or config change — use a fenced code block>
Step 3 — <verification step to confirm the fix worked>

Apply RULE 2 from your system instructions to every finding in this section.
If there are no Critical/High findings, write a single sentence stating that.

## Medium Severity Findings

For EVERY Medium finding:

### [MEDIUM] — [Finding Name]
**Endpoint:** `<url>`
**Description:** What was found and why it matters (2 sentences max).
**Exact Fix:**
<Use a fenced code block. Apply RULE 2. No generic advice.>

## Low and Informational Findings

Group by category. For each group:
- **Category name** (count): one sentence describing the findings.
  Fix: exact header, config value, or code change — one line each.

## Vulnerability Breakdown by Category

| Scanner Module | Findings | Severity Distribution |
|----------------|----------|-----------------------|
Include a row for every module (Recon, Secrets, Auth, SQLi, Path Traversal, BOLA, XSS).
In Severity Distribution, list e.g. "2 High, 1 Medium" — be specific.

## Prioritized Remediation Roadmap

Divide into three tracks. Format each item as a mini-ticket:

### Track 1 — Immediate (0–48 hours) — Critical and High
**[TICKET-N] <Title>**
- Severity: Critical / High
- Effort: <X hours>
- Owner: <Dev / DevOps / Security>
- Action: <2–3 lines — what exactly to change, where, and how to verify>

### Track 2 — Short-Term (1–2 weeks) — Medium
(same ticket format)

### Track 3 — Hardening Sprint — Low and Informational
(same ticket format)

## Security Score

Start from 10.0 and show explicit deductions:
- {sev_counts.get("Critical", 0)} Critical finding(s) × −2.5 = −<X>
- {sev_counts.get("High", 0)} High finding(s)     × −1.5 = −<X>
- {sev_counts.get("Medium", 0)} Medium finding(s)   × −0.5 = −<X>
- Bonus deductions for systemic issues (missing headers sitewide, etc.)

**Security Score: X.X / 10**

Write 2–3 sentences interpreting the score, referencing the most critical specific findings by name.

## Disclaimer

This assessment was performed by the FORTIS automated security scanner on {scan_date}.
Findings represent the security posture at the time of scanning and may not reflect
vulnerabilities introduced or remediated after this date. All findings should be
independently validated by a qualified security professional before remediation is
applied in a production environment. This report does not constitute a full manual
penetration test. FORTIS and its operators accept no liability for actions taken
based on the contents of this report.
"""

    # ── Model preference order ────────────────────────────────────────────────
    models_to_try = [
        "gemini-2.5-flash",       # Primary: best reasoning for complex prompts
        "gemini-2.5-flash-lite",  # Fallback 1: lighter 2.5 variant
        "gemini-2.0-flash",       # Fallback 2: stable 2.0 flash
        "gemini-2.0-flash-lite",  # Fallback 3: lightest stable option
    ]

    def _call_gemini(model_name: str) -> str:
        client = google_genai.Client(api_key=GEMINI_API_KEY)
        response = client.models.generate_content(
            model=model_name,
            contents=prompt,
            config=genai_types.GenerateContentConfig(
                system_instruction=system_instruction,
                max_output_tokens=8192,
                temperature=0.15,   # Lower = more deterministic, fewer hallucinations
                top_p=0.92,
            ),
        )
        return response.text

    last_error = ""
    for model_name in models_to_try:
        try:
            text = await asyncio.get_event_loop().run_in_executor(
                None, lambda m=model_name: _call_gemini(m)
            )
            return text
        except Exception as e:
            err_str = str(e)
            last_error = err_str
            # 429 = quota exceeded — try next model, don't crash immediately
            if "429" in err_str or "quota" in err_str.lower() or "RESOURCE_EXHAUSTED" in err_str:
                print(f"[FORTIS] Gemini quota hit on {model_name}, trying next model...")
                continue
            # Any other error (auth, bad request, etc.) — fail fast, no point retrying
            return (
                f"## AI Report Unavailable\n\n"
                f"Gemini API error: {err_str}\n\n"
                f"**Common fixes:**\n"
                f"- Check your `GEMINI_API_KEY` is valid in `.env`\n"
                f"- Enable billing at https://ai.dev to lift free-tier limits\n"
                f"- Visit https://ai.google.dev/gemini-api/docs/rate-limits for quota info"
            )

    # All models exhausted (all hit quota)
    return (
        "## AI Report Unavailable — Quota Exceeded\n\n"
        f"All Gemini models returned a 429 quota error.\n\n"
        f"Last error: `{last_error}`\n\n"
        "**To fix this:**\n"
        "1. Go to https://ai.dev/rate-limit to check your current usage\n"
        "2. Enable billing on your Google Cloud project to lift the free-tier limit\n"
        "3. Or wait ~24 hours for the daily free quota to reset\n\n"
        "The scan results above are complete — only the AI summary is unavailable."
    )

# ── Findings normalizer ───────────────────────────────────────────────────────

def _normalize(raw: list) -> list:
    """Ensure every finding has the same keys regardless of which scanner produced it."""
    return [
        {
            "check":       f.get("check", "Unknown"),
            "severity":    f.get("severity", "Low"),
            "description": f.get("description", ""),
            "source_url":  f.get("source_url", ""),
            "evidence":    f.get("evidence", ""),
            "category":    f.get("category", "general"),
        }
        for f in raw
    ]


# ── Core scan pipeline ────────────────────────────────────────────────────────

async def run_scan_pipeline(scan_id: str, url: str):
    """
    Full async scan pipeline:
      1. Check target is reachable
      2. Crawl the site once (shared across all scanners — efficient)
      3. Fan-out to all 7 scanner modules concurrently
      4. Merge and deduplicate findings
      5. Generate Gemini AI report
    Updates SCANS[scan_id] throughout so SSE can stream progress.
    """
    scan = SCANS[scan_id]

    def set_module(mod: str, status: str, findings: list = None, error: str = None):
        """Update a module's status inside the scan dict."""
        scan["modules"][mod] = {
            "status":   status,
            "findings": findings or [],
            "error":    error,
            "done_at":  time.time() if status in ("completed", "error") else None,
        }

    # ── 1. Reachability ───────────────────────────────────────────────────────
    scan["stage"] = "reachability"
    ok, err = await check_reachability(url)
    if not ok:
        scan["status"] = "error"
        scan["error"]  = f"Target unreachable: {err}"
        return

    # ── 2. Crawl once — reused by all scanners ────────────────────────────────
    scan["stage"] = "crawling"
    pre_crawled: dict = {}
    try:
        async with make_session(insecure=INSECURE, timeout=DEFAULT_TIMEOUT) as session:
            sem = asyncio.Semaphore(DEFAULT_MAX_CONCURRENT)
            pre_crawled = await asyncio.wait_for(
                crawl(session, url, sem, depth=CRAWL_DEPTH),
                timeout=60,
            )
        scan["crawled_urls"] = list(pre_crawled.keys())
        print(f"[FORTIS] Crawled {len(pre_crawled)} URLs")
    except Exception as e:
        scan["errors"].append(f"Crawl error: {e}")
        print(f"[FORTIS] Crawl error: {e}")

    scan["stage"] = "scanning"

    # Mark all modules as pending so frontend shows them immediately
    all_modules = ["recon", "secrets", "auth", "sqli", "path_traversal", "bola", "xss"]
    for mod in all_modules:
        set_module(mod, "pending")

    # ── 3. Scanner coroutines ─────────────────────────────────────────────────

    async def run_recon():
        set_module("recon", "running")
        try:
            r = await asyncio.wait_for(
                recon_scanner.scan(
                    url, crawl_depth=CRAWL_DEPTH,
                    insecure=INSECURE, pre_crawled=pre_crawled
                ),
                timeout=90,
            )
            set_module("recon", "completed", _normalize(r.get("findings", [])))
        except Exception as e:
            set_module("recon", "error", error=str(e))

    async def run_secrets():
        set_module("secrets", "running")
        try:
            r = await asyncio.wait_for(
                secret_scanner.scan(
                    url, crawl_depth=CRAWL_DEPTH,
                    insecure=INSECURE, pre_crawled=pre_crawled
                ),
                timeout=90,
            )
            set_module("secrets", "completed", _normalize(r.get("findings", [])))
        except Exception as e:
            set_module("secrets", "error", error=str(e))

    async def run_auth():
        set_module("auth", "running")
        try:
            r = await asyncio.wait_for(
                auth_misconfig_scanner.scan(
                    url, crawl_depth=CRAWL_DEPTH,
                    insecure=INSECURE, pre_crawled=pre_crawled
                ),
                timeout=90,
            )
            set_module("auth", "completed", _normalize(r.get("findings", [])))
        except Exception as e:
            set_module("auth", "error", error=str(e))

    async def run_sqli():
        # sqli_checker uses synchronous requests library
        # run_in_executor runs it in a thread so it doesn't block the async loop
        set_module("sqli", "running")
        try:
            raw = await asyncio.get_event_loop().run_in_executor(
                None, sqli_checker.scan, url
            )
            findings = [
                {
                    "check":       f["type"],
                    "severity":    f["severity"].capitalize(),
                    "description": f["description"],
                    "source_url":  f["url"],
                    "evidence":    f"param={f['parameter']} payload={f['payload']}",
                    "category":    "injection",
                }
                for f in (raw or [])
            ]
            set_module("sqli", "completed", findings)
        except Exception as e:
            set_module("sqli", "error", error=str(e))

    async def run_path_traversal():
        set_module("path_traversal", "running")
        try:
            result = await asyncio.wait_for(
                path_traversal_scanner.run_scanner(url),
                timeout=90,
            )
            findings = [
                {
                    "check":       f.name,
                    "severity":    f.severity.capitalize(),
                    "description": f.description,
                    "source_url":  f.endpoint,
                    "evidence":    f.evidence or f"param={f.param} method={f.method}",
                    "category":    "path_traversal",
                }
                for f in result.findings
            ]
            set_module("path_traversal", "completed", findings)
        except Exception as e:
            set_module("path_traversal", "error", error=str(e))

    async def run_bola():
        set_module("bola", "running")
        if not BOLA_AVAILABLE:
            set_module("bola", "error",
                       error="Install beautifulsoup4 to enable: pip install beautifulsoup4")
            return
        try:
            result = await asyncio.wait_for(bola.run_scanner(url), timeout=90)
            findings = [
                {
                    "check":       f.name,
                    "severity":    f.severity.capitalize(),
                    "description": f.description,
                    "source_url":  f.endpoint,
                    "evidence":    f.evidence or f"method={f.method} id={f.tested_id}",
                    "category":    f.module,
                }
                for f in result.findings
            ]
            set_module("bola", "completed", findings)
        except Exception as e:
            set_module("bola", "error", error=str(e))

    async def run_xss():
        set_module("xss", "running")
        if not XSS_AVAILABLE:
            set_module("xss", "error",
                       error="xss_scanner.py not found — place it in the same folder as main.py")
            return
        try:
            r = await asyncio.wait_for(
                xss_scanner.scan(
                    url, crawl_depth=CRAWL_DEPTH,
                    insecure=INSECURE, pre_crawled=pre_crawled
                ),
                timeout=90,
            )
            set_module("xss", "completed", _normalize(r.get("findings", [])))
        except Exception as e:
            set_module("xss", "error", error=str(e))

    # ── 4. Run ALL 7 scanners at the same time ────────────────────────────────
    # asyncio.gather starts all coroutines concurrently.
    # return_exceptions=True means one scanner crashing won't stop the others.
    await asyncio.gather(
        run_recon(),
        run_secrets(),
        run_auth(),
        run_sqli(),
        run_path_traversal(),
        run_bola(),
        run_xss(),
        return_exceptions=True,
    )

    # ── 5. Merge and deduplicate findings from all scanners ───────────────────
    scan["stage"] = "reporting"
    seen:   set  = set()
    merged: list = []

    for mod_name, mod_data in scan["modules"].items():
        for f in mod_data.get("findings", []):
            # Deduplicate by check name + url + first 60 chars of evidence
            key = (f.get("check", ""), f.get("source_url", ""), f.get("evidence", "")[:60])
            if key not in seen:
                seen.add(key)
                merged.append({**f, "module": mod_name})

    # Sort by severity: Critical first, then High, Medium, Low, Info
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    merged.sort(key=lambda f: sev_order.get(f.get("severity", ""), 99))
    scan["all_findings"] = merged

    # ── 6. Generate Gemini AI report ──────────────────────────────────────────
    scan["stage"] = "generating_report"
    summary = {
        "target": url,
        **{
            mod: {"findings": data.get("findings", [])}
            for mod, data in scan["modules"].items()
        },
    }
    scan["report"] = await generate_gemini_report(summary)

    scan["status"]       = "completed"
    scan["completed_at"] = time.time()
    print(f"[FORTIS] Scan {scan_id[:8]} complete — {len(merged)} findings")


# ── API routes ────────────────────────────────────────────────────────────────

@app.post("/api/scan", response_model=ScanResponse)
async def start_scan(req: ScanRequest):
    """
    Start a new scan.
    Returns a scan_id immediately — results stream via /api/scan/{id}/stream
    """
    scan_id = str(uuid.uuid4())
    SCANS[scan_id] = {
        "scan_id":      scan_id,
        "target":       req.url,
        "status":       "running",
        "stage":        "initializing",
        "modules":      {},
        "all_findings": [],
        "report":       None,
        "errors":       [],
        "started_at":   time.time(),
        "completed_at": None,
        "crawled_urls": [],
    }
    # create_task starts the pipeline in the background — does NOT block this response
    asyncio.create_task(run_scan_pipeline(scan_id, req.url))
    return ScanResponse(scan_id=scan_id, message="Scan started")


@app.get("/api/scan/{scan_id}/stream")
async def stream_scan(scan_id: str):
    """
    Server-Sent Events (SSE) stream.
    The frontend connects here and receives live updates as each scanner completes.

    Events emitted:
      connected       — immediately on connection
      stage_update    — when pipeline moves to a new stage
      module_update   — when a module changes status (pending→running→completed)
      module_findings — when a module completes, sends all its findings at once
      report          — when Gemini report is ready
      done            — scan fully complete
      error           — scan failed
    """
    if scan_id not in SCANS:
        raise HTTPException(status_code=404, detail="Scan not found")

    async def generate() -> AsyncGenerator[str, None]:
        last_mod_states: dict[str, str] = {}
        yield _sse("connected", {"scan_id": scan_id})

        while True:
            scan = SCANS.get(scan_id)
            if not scan:
                yield _sse("error", {"message": "Scan disappeared"})
                return

            # Always send current stage
            yield _sse("stage_update", {
                "stage":         scan.get("stage"),
                "status":        scan.get("status"),
                "crawled_count": len(scan.get("crawled_urls", [])),
            })

            # Send module updates only when status changes
            for mod, data in scan.get("modules", {}).items():
                prev = last_mod_states.get(mod)
                cur  = data.get("status")
                if cur != prev:
                    last_mod_states[mod] = cur
                    yield _sse("module_update", {
                        "module": mod,
                        "status": cur,
                        "error":  data.get("error"),
                    })
                    # Send findings immediately when module completes
                    # Frontend shows them without waiting for other scanners
                    if cur == "completed":
                        yield _sse("module_findings", {
                            "module":   mod,
                            "findings": data.get("findings", []),
                            "count":    len(data.get("findings", [])),
                        })

            # Send report once, as soon as it's ready
            if scan.get("report") and not scan.get("_report_sent"):
                scan["_report_sent"] = True
                yield _sse("report", {"content": scan["report"]})

            if scan.get("status") == "completed":
                yield _sse("done", {
                    "total_findings": len(scan.get("all_findings", [])),
                    "duration": round(time.time() - scan.get("started_at", time.time()), 1),
                })
                return

            if scan.get("status") == "error":
                yield _sse("error", {"message": scan.get("error", "Unknown error")})
                return

            # Poll every 1.5 seconds
            await asyncio.sleep(1.5)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":    "no-cache",
            "X-Accel-Buffering": "no",   # disable nginx buffering if behind proxy
            "Connection":        "keep-alive",
        },
    )


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str):
    """Return the full scan result as JSON (use after stream ends)."""
    if scan_id not in SCANS:
        raise HTTPException(status_code=404, detail="Scan not found")
    return SCANS[scan_id]


# ── PDF Report Generation ─────────────────────────────────────────────────────

def _build_pdf_report(scan: dict) -> bytes:
    """
    Generate a professional PDF security report from scan data.
    Uses reportlab Platypus for structured, multi-page output.
    Returns raw PDF bytes.
    """
    import io
    from datetime import datetime
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak, KeepTogether
    )
    from reportlab.platypus.flowables import HRFlowable

    buf = io.BytesIO()
    target   = scan.get("target", "Unknown")
    findings = scan.get("all_findings", [])
    report_md = scan.get("report", "") or ""
    scan_time = scan.get("started_at", 0)
    duration  = round(scan.get("completed_at", scan_time) - scan_time, 1)
    scan_date = datetime.utcfromtimestamp(scan_time).strftime("%B %d, %Y")
    scan_time_str = datetime.utcfromtimestamp(scan_time).strftime("%H:%M UTC")

    # ── Colour palette ────────────────────────────────────────────────────────
    DARK_BG    = colors.HexColor("#0D1117")
    ACCENT     = colors.HexColor("#00BFFF")  # FORTIS blue
    TEXT_DARK  = colors.HexColor("#1A1A2E")
    CARD_BG    = colors.HexColor("#F4F6F9")
    SEV_COLORS = {
        "Critical": colors.HexColor("#FF3B3B"),
        "High":     colors.HexColor("#FF7043"),
        "Medium":   colors.HexColor("#FFA726"),
        "Low":      colors.HexColor("#66BB6A"),
        "Info":     colors.HexColor("#42A5F5"),
    }

    # ── Styles ────────────────────────────────────────────────────────────────
    base = getSampleStyleSheet()
    styles = {
        "title": ParagraphStyle("FTitle",
            fontSize=28, leading=34, textColor=colors.white,
            fontName="Helvetica-Bold", alignment=TA_CENTER, spaceAfter=4),
        "subtitle": ParagraphStyle("FSubtitle",
            fontSize=12, leading=16, textColor=colors.HexColor("#AAD4FF"),
            fontName="Helvetica", alignment=TA_CENTER, spaceAfter=2),
        "label": ParagraphStyle("FLabel",
            fontSize=9, textColor=colors.HexColor("#888888"),
            fontName="Helvetica", alignment=TA_CENTER),
        "h1": ParagraphStyle("FH1",
            fontSize=16, leading=20, textColor=DARK_BG,
            fontName="Helvetica-Bold", spaceBefore=14, spaceAfter=6,
            borderPad=4),
        "h2": ParagraphStyle("FH2",
            fontSize=13, leading=17, textColor=ACCENT,
            fontName="Helvetica-Bold", spaceBefore=10, spaceAfter=4),
        "body": ParagraphStyle("FBody",
            fontSize=10, leading=15, textColor=TEXT_DARK,
            fontName="Helvetica", spaceAfter=6, alignment=TA_JUSTIFY),
        "mono": ParagraphStyle("FMono",
            fontSize=8.5, leading=13, textColor=colors.HexColor("#2D2D2D"),
            fontName="Courier", spaceAfter=4,
            backColor=colors.HexColor("#F0F0F0"), leftIndent=8, rightIndent=8),
        "finding_title": ParagraphStyle("FFTitle",
            fontSize=11, leading=14, textColor=colors.white,
            fontName="Helvetica-Bold"),
        "finding_body": ParagraphStyle("FFBody",
            fontSize=9.5, leading=14, textColor=TEXT_DARK,
            fontName="Helvetica", spaceAfter=3),
        "tag": ParagraphStyle("FTag",
            fontSize=8, textColor=colors.white,
            fontName="Helvetica-Bold", alignment=TA_CENTER),
        "footer": ParagraphStyle("FFooter",
            fontSize=8, textColor=colors.HexColor("#AAAAAA"),
            fontName="Helvetica", alignment=TA_CENTER),
        "score_big": ParagraphStyle("FScore",
            fontSize=48, leading=52, textColor=ACCENT,
            fontName="Helvetica-Bold", alignment=TA_CENTER),
        "score_label": ParagraphStyle("FScoreLabel",
            fontSize=12, textColor=colors.HexColor("#555555"),
            fontName="Helvetica", alignment=TA_CENTER),
    }

    # ── Page template with header/footer ─────────────────────────────────────
    PAGE_W, PAGE_H = A4
    MARGIN = 18 * mm

    def on_page(canvas, doc):
        canvas.saveState()
        # Top bar
        canvas.setFillColor(DARK_BG)
        canvas.rect(0, PAGE_H - 14*mm, PAGE_W, 14*mm, fill=1, stroke=0)
        canvas.setFillColor(ACCENT)
        canvas.setFont("Helvetica-Bold", 9)
        canvas.drawString(MARGIN, PAGE_H - 9*mm, "FORTIS Security Report")
        canvas.setFillColor(colors.HexColor("#AAAAAA"))
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(PAGE_W - MARGIN, PAGE_H - 9*mm,
                               f"{target}  |  {scan_date}")
        # Bottom bar
        canvas.setFillColor(colors.HexColor("#EEEEEE"))
        canvas.rect(0, 0, PAGE_W, 10*mm, fill=1, stroke=0)
        canvas.setFillColor(colors.HexColor("#888888"))
        canvas.setFont("Helvetica", 7.5)
        canvas.drawString(MARGIN, 3.5*mm,
            "Confidential — FORTIS Automated Security Scanner. For authorized use only.")
        canvas.drawRightString(PAGE_W - MARGIN, 3.5*mm,
            f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=18*mm, bottomMargin=14*mm,
        title=f"FORTIS Security Report — {target}",
        author="FORTIS Security Scanner",
        subject="Web Application Vulnerability Assessment",
    )

    story = []

    # ══════════════════════════════════════════════════════════════════════════
    # COVER PAGE
    # ══════════════════════════════════════════════════════════════════════════
    story.append(Spacer(1, 30*mm))

    # Dark cover banner
    cover_data = [[Paragraph("FORTIS", styles["title"]),
                   Paragraph("Web Application Security Report", styles["subtitle"])]]
    cover_table = Table(cover_data, colWidths=[PAGE_W - 2*MARGIN])
    cover_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), DARK_BG),
        ("TOPPADDING",    (0,0), (-1,-1), 20),
        ("BOTTOMPADDING", (0,0), (-1,-1), 20),
        ("LEFTPADDING",   (0,0), (-1,-1), 16),
        ("RIGHTPADDING",  (0,0), (-1,-1), 16),
        ("ROUNDEDCORNERS", [6]),
    ]))
    story.append(cover_table)
    story.append(Spacer(1, 10*mm))

    # Meta info grid
    sev_counts = {}
    for f in findings:
        s = f.get("severity", "Info")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    meta_rows = [
        [
            _cover_cell("Target", target, styles),
            _cover_cell("Scan Date", f"{scan_date}\n{scan_time_str}", styles),
        ],
        [
            _cover_cell("Total Findings", str(len(findings)), styles),
            _cover_cell("Scan Duration", f"{duration}s", styles),
        ],
        [
            _cover_cell("Critical / High",
                f"{sev_counts.get('Critical',0)} / {sev_counts.get('High',0)}", styles),
            _cover_cell("Medium / Low",
                f"{sev_counts.get('Medium',0)} / {sev_counts.get('Low',0)}", styles),
        ],
    ]
    meta_table = Table(meta_rows, colWidths=[(PAGE_W-2*MARGIN)/2]*2,
                       hAlign="CENTER")
    meta_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), CARD_BG),
        ("TOPPADDING",    (0,0), (-1,-1), 10),
        ("BOTTOMPADDING", (0,0), (-1,-1), 10),
        ("LEFTPADDING",   (0,0), (-1,-1), 14),
        ("RIGHTPADDING",  (0,0), (-1,-1), 14),
        ("GRID",          (0,0), (-1,-1), 0.5, colors.HexColor("#DDDDDD")),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 8*mm))

    # Severity pills row
    pill_cells = []
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        cnt = sev_counts.get(sev, 0)
        c   = SEV_COLORS.get(sev, colors.grey)
        pill_cells.append(_sev_pill(sev, cnt, c, styles))
    pills = Table([pill_cells],
                  colWidths=[(PAGE_W-2*MARGIN)/5]*5, hAlign="CENTER")
    pills.setStyle(TableStyle([
        ("TOPPADDING",    (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ("LEFTPADDING",   (0,0), (-1,-1), 4),
        ("RIGHTPADDING",  (0,0), (-1,-1), 4),
    ]))
    story.append(pills)
    story.append(PageBreak())

    # ══════════════════════════════════════════════════════════════════════════
    # AI REPORT CONTENT (parsed from markdown)
    # ══════════════════════════════════════════════════════════════════════════
    story.append(Paragraph("AI Security Assessment", styles["h1"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=ACCENT, spaceAfter=8))

    if report_md:
        _md_to_story(report_md, story, styles, SEV_COLORS)
    else:
        story.append(Paragraph(
            "AI report was not generated for this scan.", styles["body"]))

    story.append(PageBreak())

    # ══════════════════════════════════════════════════════════════════════════
    # DETAILED FINDINGS TABLE
    # ══════════════════════════════════════════════════════════════════════════
    story.append(Paragraph("Detailed Findings", styles["h1"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=ACCENT, spaceAfter=8))

    if findings:
        for i, f in enumerate(findings, 1):
            sev   = f.get("severity", "Info")
            sev_c = SEV_COLORS.get(sev, colors.grey)
            block = _finding_block(i, f, sev_c, styles, PAGE_W, MARGIN)
            story.append(KeepTogether(block))
            story.append(Spacer(1, 4))
    else:
        story.append(Paragraph(
            "No findings were recorded for this scan.", styles["body"]))

    story.append(PageBreak())

    # ══════════════════════════════════════════════════════════════════════════
    # MODULE SUMMARY TABLE
    # ══════════════════════════════════════════════════════════════════════════
    story.append(Paragraph("Module Summary", styles["h1"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=ACCENT, spaceAfter=10))

    mod_header = [
        Paragraph("<b>Module</b>", styles["finding_body"]),
        Paragraph("<b>Status</b>", styles["finding_body"]),
        Paragraph("<b>Findings</b>", styles["finding_body"]),
        Paragraph("<b>Critical</b>", styles["finding_body"]),
        Paragraph("<b>High</b>", styles["finding_body"]),
        Paragraph("<b>Medium</b>", styles["finding_body"]),
        Paragraph("<b>Low</b>", styles["finding_body"]),
    ]
    mod_rows = [mod_header]
    MODULE_LABELS = {
        "recon": "🔍 Recon", "secrets": "🔑 Secrets", "auth": "🔒 Auth",
        "sqli": "💉 SQLi", "path_traversal": "📂 Path Traversal",
        "bola": "🎯 BOLA/IDOR", "dynamic": "🌐 Dynamic",
    }
    for mod_id, mod_data in scan.get("modules", {}).items():
        mf = mod_data.get("findings", [])
        mc = {s: sum(1 for x in mf if x.get("severity") == s)
              for s in ["Critical","High","Medium","Low"]}
        status = mod_data.get("status", "pending")
        status_color = {"completed": colors.HexColor("#2E7D32"),
                        "error":     colors.HexColor("#B71C1C"),
                        "running":   colors.HexColor("#1565C0"),
                        "pending":   colors.HexColor("#555555")}.get(status, colors.grey)
        mod_rows.append([
            Paragraph(MODULE_LABELS.get(mod_id, mod_id), styles["finding_body"]),
            Paragraph(f'<font color="{status_color.hexval() if hasattr(status_color,"hexval") else "#555555"}">{status.capitalize()}</font>',
                      styles["finding_body"]),
            Paragraph(str(len(mf)), styles["finding_body"]),
            Paragraph(str(mc["Critical"]), styles["finding_body"]),
            Paragraph(str(mc["High"]),     styles["finding_body"]),
            Paragraph(str(mc["Medium"]),   styles["finding_body"]),
            Paragraph(str(mc["Low"]),      styles["finding_body"]),
        ])

    col_w = (PAGE_W - 2*MARGIN)
    mod_table = Table(mod_rows,
                      colWidths=[col_w*0.22, col_w*0.12, col_w*0.12,
                                 col_w*0.135, col_w*0.135, col_w*0.135, col_w*0.135])
    mod_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), DARK_BG),
        ("TEXTCOLOR",     (0,0), (-1,0), colors.white),
        ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 9),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [colors.white, CARD_BG]),
        ("GRID",          (0,0), (-1,-1), 0.4, colors.HexColor("#DDDDDD")),
        ("TOPPADDING",    (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ("RIGHTPADDING",  (0,0), (-1,-1), 8),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
    ]))
    story.append(mod_table)

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    return buf.getvalue()


def _cover_cell(label: str, value: str, styles: dict):
    """Helper: two-line label+value cell for cover page."""
    from reportlab.platypus import Paragraph
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.enums import TA_LEFT
    lbl = Paragraph(f'<font size="8" color="#888888">{label}</font>', styles["label"])
    val = Paragraph(f'<font size="12"><b>{value}</b></font>', styles["body"])
    return [lbl, val]


def _sev_pill(label: str, count: int, color, styles: dict):
    """Helper: coloured severity pill for cover page."""
    from reportlab.platypus import Paragraph, Table
    from reportlab.platypus.flowables import KeepTogether
    from reportlab.lib import colors
    from reportlab.platypus import TableStyle
    cell = Table([[Paragraph(f'<b>{count}</b>', styles["score_label"])],
                  [Paragraph(label, styles["label"])]],
                 colWidths=["100%"])
    cell.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), color),
        ("TEXTCOLOR",     (0,0), (-1,-1), colors.white),
        ("TOPPADDING",    (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ("ALIGN",         (0,0), (-1,-1), "CENTER"),
        ("ROUNDEDCORNERS", [5]),
    ]))
    return cell


def _finding_block(idx: int, f: dict, sev_color, styles: dict, page_w, margin):
    """Helper: render one finding as a styled card."""
    from reportlab.platypus import Paragraph, Table, Spacer, HRFlowable
    from reportlab.platypus import TableStyle as TS
    from reportlab.lib import colors

    sev   = f.get("severity", "Info")
    check = f.get("check", "Unknown Finding")
    desc  = f.get("description", "—")
    url   = f.get("source_url", "—")
    evid  = f.get("evidence", "")
    cat   = f.get("category", "general")
    mod   = f.get("module", "")
    col_w = page_w - 2*margin

    # Header row: index + name on dark bg, severity badge on right
    header = Table([[
        Paragraph(f'<font color="white"><b>#{idx}  {check}</b></font>',
                  styles["finding_title"]),
        Paragraph(f'<font color="white"><b>{sev}</b></font>',
                  styles["tag"]),
    ]], colWidths=[col_w*0.82, col_w*0.18])
    header.setStyle(TS([
        ("BACKGROUND",    (0,0), (-1,-1), sev_color),
        ("TOPPADDING",    (0,0), (-1,-1), 7),
        ("BOTTOMPADDING", (0,0), (-1,-1), 7),
        ("LEFTPADDING",   (0,0), (0,-1),  10),
        ("RIGHTPADDING",  (-1,0),(-1,-1), 10),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("ALIGN",         (1,0), (1,-1),  "CENTER"),
    ]))

    def row(label, value):
        return [
            Paragraph(f'<font size="8.5" color="#555555"><b>{label}</b></font>',
                      styles["finding_body"]),
            Paragraph(f'<font size="9">{str(value)[:300]}</font>',
                      styles["finding_body"]),
        ]

    body_data = [row("Category", f"{cat} / {mod}"),
                 row("Endpoint", url),
                 row("Description", desc)]
    if evid:
        body_data.append(row("Evidence", evid))

    body = Table(body_data, colWidths=[col_w*0.18, col_w*0.82])
    body.setStyle(TS([
        ("BACKGROUND",    (0,0), (-1,-1), colors.HexColor("#F9FAFB")),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING",   (0,0), (-1,-1), 10),
        ("RIGHTPADDING",  (0,0), (-1,-1), 10),
        ("LINEBELOW",     (0,0), (-1,-2), 0.3, colors.HexColor("#EEEEEE")),
        ("VALIGN",        (0,0), (-1,-1), "TOP"),
    ]))

    return [header, body, Spacer(1, 2)]


def _md_to_story(md_text: str, story: list, styles: dict, sev_colors: dict):
    """
    Minimal markdown → ReportLab flowable converter.
    Handles: ## headings, ### headings, **bold**, bullet lists, code blocks, plain paragraphs.
    """
    from reportlab.platypus import Paragraph, Spacer, HRFlowable
    from reportlab.lib import colors

    in_code = False
    code_buf = []

    def flush_code():
        nonlocal code_buf
        if code_buf:
            story.append(Paragraph("<br/>".join(
                line.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
                for line in code_buf
            ), styles["mono"]))
            code_buf.clear()

    for raw_line in md_text.splitlines():
        line = raw_line.rstrip()

        # Code fence
        if line.startswith("```"):
            if in_code:
                flush_code()
                in_code = False
            else:
                in_code = True
            continue
        if in_code:
            code_buf.append(line)
            continue

        # Headings
        if line.startswith("## "):
            text = line[3:].strip()
            story.append(Spacer(1, 4))
            story.append(Paragraph(text, styles["h1"]))
            story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#DDDDDD"), spaceAfter=4))
            continue
        if line.startswith("### "):
            story.append(Paragraph(line[4:].strip(), styles["h2"]))
            continue
        if line.startswith("#### "):
            story.append(Paragraph(f"<b>{line[5:].strip()}</b>", styles["body"]))
            continue

        # Horizontal rule
        if line.startswith("---"):
            story.append(HRFlowable(width="100%", thickness=0.5,
                                    color=colors.HexColor("#CCCCCC"), spaceAfter=4))
            continue

        # Bullet list items
        if line.startswith("- ") or line.startswith("* "):
            text = _inline_md(line[2:])
            story.append(Paragraph(f"&bull;  {text}", styles["body"]))
            continue
        if len(line) > 2 and line[0].isdigit() and line[1] in ".)" :
            text = _inline_md(line[2:].lstrip())
            story.append(Paragraph(f"{line[0]}.  {text}", styles["body"]))
            continue

        # Blank line
        if not line.strip():
            story.append(Spacer(1, 4))
            continue

        # Normal paragraph
        story.append(Paragraph(_inline_md(line), styles["body"]))

    flush_code()


def _inline_md(text: str) -> str:
    """Convert inline markdown (**bold**, `code`, *italic*) to ReportLab XML."""
    import re
    # Bold
    text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
    # Italic
    text = re.sub(r"\*(.+?)\*", r"<i>\1</i>", text)
    # Inline code
    text = re.sub(r"`(.+?)`",
                  r'<font name="Courier" size="8.5" backColor="#F0F0F0">\1</font>',
                  text)
    # Escape bare ampersands that aren't already entities
    text = re.sub(r"&(?!amp;|lt;|gt;|quot;|apos;|#)", "&amp;", text)
    return text


@app.get("/api/scan/{scan_id}/report.pdf")
async def download_pdf_report(scan_id: str):
    """
    Generate and stream a professional PDF security report for the given scan.
    Frontend calls this after the scan is complete.
    """
    if scan_id not in SCANS:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan = SCANS[scan_id]
    if scan.get("status") not in ("completed", "error"):
        raise HTTPException(status_code=409,
                            detail="Scan is still running — wait for completion")

    try:
        pdf_bytes = await asyncio.get_event_loop().run_in_executor(
            None, _build_pdf_report, scan
        )
    except Exception as e:
        raise HTTPException(status_code=500,
                            detail=f"PDF generation failed: {e}")

    from fastapi.responses import Response
    from urllib.parse import quote
    target_safe = scan.get("target", "scan").replace("https://", "").replace("http://", "").split("/")[0]
    filename = f"FORTIS_{target_safe}_{scan_id[:8]}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(pdf_bytes)),
        },
    )


@app.get("/api/modules")
async def get_modules():
    """
    Frontend calls this once on load.
    Returns the list of available scanner modules so the sidebar
    and module pages are built dynamically — no hardcoding in the frontend.
    """
    return {
        "modules": [
            {
                "id":          "recon",
                "label":       "Recon",
                "icon":        "🔍",
                "description": "Headers, CORS, SSL, sensitive file exposure",
                "available":   True,
            },
            {
                "id":          "secrets",
                "label":       "Secrets",
                "icon":        "🔑",
                "description": "API keys, tokens, hardcoded credentials",
                "available":   True,
            },
            {
                "id":          "auth",
                "label":       "Auth",
                "icon":        "🔒",
                "description": "JWT, cookies, client-side auth checks",
                "available":   True,
            },
            {
                "id":          "sqli",
                "label":       "SQL Injection",
                "icon":        "💉",
                "description": "Error-based, boolean & time-based SQLi",
                "available":   True,
            },
            {
                "id":          "path_traversal",
                "label":       "Path Traversal",
                "icon":        "📂",
                "description": "Directory traversal, file access, null byte injection",
                "available":   True,
            },
            {
                "id":          "bola",
                "label":       "BOLA / IDOR",
                "icon":        "🎯",
                "description": "12-module broken object level access testing",
                "available":   BOLA_AVAILABLE,
            },
            {
                "id":          "xss",
                "label":       "XSS",
                "icon":        "⚡",
                "description": "Passive DOM sink/source analysis, reflection & CSP checks",
                "available":   XSS_AVAILABLE,
            },
        ],
        "config": {
            "crawl_depth":    CRAWL_DEPTH,
            "scan_timeout":   SCAN_TIMEOUT,
            "gemini_enabled": bool(GEMINI_API_KEY),
        },
    }


@app.get("/health")
async def health():
    """Quick status check — useful to verify the server is running."""
    return {
        "status":           "ok",
        "version":          "1.0.0",
        "gemini_enabled":   bool(GEMINI_API_KEY),
        "bola_available":   BOLA_AVAILABLE,
        "xss_available":    XSS_AVAILABLE,
        "crawl_depth":      CRAWL_DEPTH,
    }


# ── Dev runner ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    print(f"""
╔══════════════════════════════════════════╗
║         FORTIS Security Scanner          ║
║         http://{HOST}:{PORT}             ║
╚══════════════════════════════════════════╝
  Gemini AI   : {"✓ configured" if GEMINI_API_KEY else "✗ no key in .env"}
  BOLA        : {"✓ available" if BOLA_AVAILABLE else "✗ install beautifulsoup4"}
  XSS Scanner : {"✓ available" if XSS_AVAILABLE else "✗ xss_scanner.py not found"}
  Crawl depth : {CRAWL_DEPTH}
""")
    uvicorn.run("main:app", host=HOST, port=PORT, reload=True)