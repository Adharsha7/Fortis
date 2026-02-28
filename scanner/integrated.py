"""
╔══════════════════════════════════════════════════════════════╗
║           FORTIS - Vulnerability Scanner Suite               ║
║  Modules: AI Misconfiguration | Cloud Keys | JWT | Files     ║
╚══════════════════════════════════════════════════════════════╝

Usage:
    python fortis_scanner.py --url http://localhost:5000
    python fortis_scanner.py --url https://example.com --verbose
    python fortis_scanner.py --url https://example.com --output report.json
    python fortis_scanner.py --url https://example.com --modules ai jwt
"""

import argparse
import base64
import json
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

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
    severity: str        # CRITICAL | HIGH | MEDIUM | LOW | INFO
    module: str
    title: str
    description: str
    evidence: str = ""
    recommendation: str = ""
    url: str = ""

@dataclass
class ScanResult:
    target: str
    findings: list[Finding] = field(default_factory=list)
    errors:   list[str]    = field(default_factory=list)
    urls_hit: list[str]    = field(default_factory=list)

SEVERITY_ORDER  = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[93m",
    "MEDIUM":   "\033[94m",
    "LOW":      "\033[96m",
    "INFO":     "\033[37m",
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
    s.headers.update({"User-Agent": "Fortis-Scanner/1.0 (SecurityResearch)"})
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


def safe_post(session, url, payload, verbose=False) -> Optional[requests.Response]:
    try:
        r = session.post(url, json=payload, timeout=session.timeout, verify=False)
        if verbose:
            print(f"    [{r.status_code}] POST {url}")
        return r
    except Exception:
        return None

# ══════════════════════════════════════════════
#  MODULE 1 – Cloud / API Key Exposure
# ══════════════════════════════════════════════

CLOUD_KEY_PATTERNS = {
    "AWS Access Key":    r'AKIA[0-9A-Z]{16}',
    "AWS Session Token": r'ASIA[0-9A-Z]{16}',
    "OpenAI Key":        r'sk-[a-zA-Z0-9]{20,}',
    "Anthropic Key":     r'sk-ant-[A-Za-z0-9\-_]{50,}',
    "Google API Key":    r'AIza[0-9A-Za-z\-_]{35}',
    "HuggingFace Token": r'hf_[A-Za-z0-9]{30,}',
    "Replicate Token":   r'r8_[A-Za-z0-9]{35,}',
    "Firebase URL":      r'https://[a-zA-Z0-9\-]+\.firebaseio\.com',
    "Generic API Key":   r'api[_\-]?key["\']?\s*[:=]\s*["\'][A-Za-z0-9\-_]{16,}',
    "Generic Secret":    r'secret[_\-]?key["\']?\s*[:=]\s*["\'][A-Za-z0-9\-_]{16,}',
    "Bearer Token":      r'Bearer\s+[A-Za-z0-9\-_\.]{30,}',
    "Private Key Header":r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
}

def module_cloud_keys(session, base_url, result, verbose):
    print(f"\n  {'─'*50}")
    print(f"  🔑  MODULE: Cloud / API Key Exposure")
    print(f"  {'─'*50}")

    # Check homepage + common JS paths
    targets = [base_url]
    for js in ["/static/js/main.js", "/assets/js/app.js", "/bundle.js",
               "/app.js", "/main.js", "/index.js"]:
        targets.append(urljoin(base_url, js))

    # Extract JS links from homepage
    home = safe_get(session, base_url, verbose)
    if home:
        js_links = re.findall(
            r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', home.text)
        for link in js_links[:15]:
            targets.append(urljoin(base_url, link))

    for url in targets:
        resp = safe_get(session, url, verbose)
        if not resp or resp.status_code != 200:
            continue
        result.urls_hit.append(url)
        content = resp.text

        for name, pattern in CLOUD_KEY_PATTERNS.items():
            for match in re.findall(pattern, content):
                if len(set(match)) < 4:
                    continue
                masked = match[:6] + "****" + match[-4:] if len(match) > 12 else match
                result.findings.append(Finding(
                    severity="CRITICAL",
                    module="Cloud/API Key Exposure",
                    title=f"Exposed {name}",
                    description=(
                        f"A {name} was found in publicly accessible content. "
                        "Attackers can use this to access cloud services, incur costs, "
                        "or exfiltrate data."
                    ),
                    evidence=f"URL: {url}\nValue: {masked}",
                    recommendation=(
                        "Remove all secrets from source code and JS files. "
                        "Use environment variables server-side. Rotate the exposed key immediately."
                    ),
                    url=url,
                ))
        time.sleep(0.05)

# ══════════════════════════════════════════════
#  MODULE 2 – JWT Security
# ══════════════════════════════════════════════

JWT_REGEX = r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*'

WEAK_SECRETS = [
    "secret", "password", "123456", "weaksecret", "test",
    "key", "jwt", "token", "admin", "qwerty", "letmein"
]

def decode_b64(data: str) -> Optional[str]:
    try:
        padding = '=' * (-len(data) % 4)
        return base64.urlsafe_b64decode(data + padding).decode('utf-8')
    except Exception:
        return None


def module_jwt(session, base_url, result, verbose):
    print(f"\n  {'─'*50}")
    print(f"  🔐  MODULE: JWT Token Security")
    print(f"  {'─'*50}")

    # Check homepage + token endpoint
    check_urls = [base_url,
                  urljoin(base_url, "/generate-token"),
                  urljoin(base_url, "/api/token"),
                  urljoin(base_url, "/auth/token"),
                  urljoin(base_url, "/login")]

    all_tokens = set()

    for url in check_urls:
        resp = safe_get(session, url, verbose)
        if not resp or resp.status_code != 200:
            continue
        result.urls_hit.append(url)
        content = resp.text + json.dumps(dict(resp.headers))

        # localStorage check
        if "localStorage.setItem" in resp.text:
            result.findings.append(Finding(
                severity="MEDIUM",
                module="JWT Security",
                title="JWT Stored in localStorage",
                description=(
                    "The app stores JWT tokens in localStorage, which is "
                    "accessible via JavaScript and vulnerable to XSS attacks."
                ),
                evidence=f"URL: {url}\nFound: localStorage.setItem",
                recommendation="Store JWTs in HttpOnly cookies instead of localStorage.",
                url=url,
            ))

        for token in re.findall(JWT_REGEX, content):
            all_tokens.add(token)

    for token in all_tokens:
        parts = token.split(".")
        if len(parts) != 3:
            continue

        header_raw   = decode_b64(parts[0])
        payload_raw  = decode_b64(parts[1])
        sig          = parts[2]

        # Algorithm: none
        if header_raw:
            try:
                hdr = json.loads(header_raw)
                alg = hdr.get("alg", "")
                if alg.lower() == "none":
                    result.findings.append(Finding(
                        severity="CRITICAL",
                        module="JWT Security",
                        title="JWT Algorithm Set to 'none'",
                        description=(
                            "JWT uses 'none' algorithm — signature is not verified. "
                            "Attackers can forge any payload without a secret key."
                        ),
                        evidence=f"Header: {header_raw}\nToken: {token[:40]}...",
                        recommendation="Enforce HS256/RS256. Reject tokens with alg=none server-side.",
                        url=base_url,
                    ))
                elif alg in ("HS256", "HS384", "HS512"):
                    # Blank/empty signature check
                    if not sig:
                        result.findings.append(Finding(
                            severity="HIGH",
                            module="JWT Security",
                            title="JWT with Empty Signature",
                            description="JWT token has an empty signature — may be accepted by misconfigured servers.",
                            evidence=f"Token: {token[:60]}...",
                            recommendation="Validate JWT signature server-side on every request.",
                            url=base_url,
                        ))
            except Exception:
                pass

        # Missing expiry
        if payload_raw:
            try:
                payload = json.loads(payload_raw)
                if "exp" not in payload:
                    result.findings.append(Finding(
                        severity="MEDIUM",
                        module="JWT Security",
                        title="JWT Missing Expiration (exp) Claim",
                        description=(
                            "The JWT token has no expiration claim. "
                            "Stolen tokens remain valid indefinitely."
                        ),
                        evidence=f"Payload: {payload_raw[:200]}",
                        recommendation="Always set 'exp' claim. Recommended: 15 min for access tokens.",
                        url=base_url,
                    ))
                if "iat" not in payload:
                    result.findings.append(Finding(
                        severity="LOW",
                        module="JWT Security",
                        title="JWT Missing Issued-At (iat) Claim",
                        description="Missing 'iat' claim makes token age verification impossible.",
                        evidence=f"Payload keys: {list(payload.keys())}",
                        recommendation="Include 'iat' claim in all JWT tokens.",
                        url=base_url,
                    ))
                # Sensitive data in payload
                sensitive_keys = ["password", "secret", "api_key", "credit_card", "ssn", "dob"]
                found_sensitive = [k for k in payload if k.lower() in sensitive_keys]
                if found_sensitive:
                    result.findings.append(Finding(
                        severity="HIGH",
                        module="JWT Security",
                        title="Sensitive Data in JWT Payload",
                        description=(
                            f"JWT payload contains sensitive fields: {found_sensitive}. "
                            "JWT payloads are base64-encoded, NOT encrypted — anyone can read them."
                        ),
                        evidence=f"Fields found: {found_sensitive}",
                        recommendation="Never store sensitive data in JWT payload. Encrypt if needed.",
                        url=base_url,
                    ))
            except Exception:
                pass

# ══════════════════════════════════════════════
#  MODULE 3 – Sensitive File Exposure
# ══════════════════════════════════════════════

SENSITIVE_PATHS = [
    ("/.env",               "CRITICAL", "Environment file with secrets"),
    ("/.env.local",         "CRITICAL", "Local environment file"),
    ("/.env.production",    "CRITICAL", "Production environment file"),
    ("/.env.backup",        "CRITICAL", "Backup environment file"),
    ("/.git/config",        "HIGH",     "Git configuration"),
    ("/.git/HEAD",          "HIGH",     "Git repository exposed"),
    ("/backup.zip",         "HIGH",     "Backup archive"),
    ("/backup.tar.gz",      "HIGH",     "Backup archive"),
    ("/database.sql",       "CRITICAL", "Database dump"),
    ("/db.sql",             "CRITICAL", "Database dump"),
    ("/config.bak",         "HIGH",     "Config backup"),
    ("/config.json",        "HIGH",     "Configuration file"),
    ("/settings.json",      "HIGH",     "Settings file"),
    ("/.htaccess",          "MEDIUM",   "Apache config"),
    ("/.DS_Store",          "LOW",      "MacOS metadata"),
    ("/wp-config.php",      "CRITICAL", "WordPress config"),
    ("/phpinfo.php",        "MEDIUM",   "PHP info page"),
    ("/server-status",      "MEDIUM",   "Apache server status"),
    ("/actuator/env",       "HIGH",     "Spring Boot env actuator"),
    ("/actuator/heapdump",  "HIGH",     "JVM heap dump"),
    ("/package.json",       "LOW",      "Node.js package manifest"),
    ("/requirements.txt",   "LOW",      "Python dependencies"),
    ("/Dockerfile",         "MEDIUM",   "Docker configuration"),
    ("/docker-compose.yml", "HIGH",     "Docker Compose config"),
    ("/id_rsa",             "CRITICAL", "Private SSH key"),
    ("/private.key",        "CRITICAL", "Private key file"),
]

SECRET_KEYWORDS = [
    "DB_PASSWORD", "DATABASE_PASSWORD", "MYSQL_PASSWORD",
    "API_KEY", "SECRET_KEY", "SECRET",
    "ACCESS_KEY", "PRIVATE_KEY", "AWS_SECRET",
    "BEGIN RSA PRIVATE KEY", "BEGIN PRIVATE KEY",
    "password", "passwd", "credentials",
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
]

def module_sensitive_files(session, base_url, result, verbose):
    print(f"\n  {'─'*50}")
    print(f"  📁  MODULE: Sensitive File Exposure")
    print(f"  {'─'*50}")

    for path, default_severity, label in SENSITIVE_PATHS:
        url = urljoin(base_url, path)
        resp = safe_get(session, url, verbose)
        if not resp or resp.status_code != 200 or len(resp.text) < 10:
            continue
        result.urls_hit.append(url)

        found_keywords = [k for k in SECRET_KEYWORDS if k in resp.text]
        severity = "CRITICAL" if found_keywords else default_severity

        result.findings.append(Finding(
            severity=severity,
            module="Sensitive File Exposure",
            title=f"Exposed: {label} ({path})",
            description=(
                f"The file {path} is publicly accessible. "
                + (f"Contains sensitive keywords: {found_keywords}." if found_keywords
                   else "May contain sensitive configuration.")
            ),
            evidence=f"URL: {url}\nHTTP 200\nContent preview: {resp.text[:200]}",
            recommendation=(
                f"Block access to {path} via web server config. "
                "Add to .gitignore. Never deploy secrets to public paths."
            ),
            url=url,
        ))
        time.sleep(0.05)

# ══════════════════════════════════════════════
#  MODULE 4 – AI Misconfiguration Exposure
# ══════════════════════════════════════════════

AI_ENDPOINTS = [
    ("/v1/chat/completions", "CRITICAL", "OpenAI-compatible LLM inference"),
    ("/v1/completions",      "CRITICAL", "OpenAI completion endpoint"),
    ("/v1/embeddings",       "HIGH",     "Embeddings endpoint"),
    ("/v1/models",           "MEDIUM",   "Model listing endpoint"),
    ("/api/chat",            "HIGH",     "Chat API"),
    ("/api/generate",        "HIGH",     "Generation endpoint"),
    ("/api/completion",      "HIGH",     "Completion endpoint"),
    ("/api/ai/query",        "HIGH",     "AI query endpoint"),
    ("/langchain/query",     "HIGH",     "LangChain endpoint"),
    ("/chain/run",           "HIGH",     "LangChain chain runner"),
    ("/rag/query",           "HIGH",     "RAG pipeline"),
    ("/llm/query",           "HIGH",     "LLM query"),
    ("/predict",             "HIGH",     "ML prediction endpoint"),
    ("/inference",           "HIGH",     "Inference endpoint"),
    ("/mlflow",              "MEDIUM",   "MLflow UI"),
    ("/mlflow/api",          "HIGH",     "MLflow API"),
    ("/ai/config",           "CRITICAL", "AI config endpoint"),
    ("/ai/admin",            "CRITICAL", "AI admin panel"),
    ("/ai/debug",            "HIGH",     "AI debug endpoint"),
    ("/metrics",             "MEDIUM",   "Prometheus metrics"),
    ("/actuator",            "MEDIUM",   "Spring actuator"),
    ("/jupyter",             "CRITICAL", "Jupyter notebook"),
    ("/lab",                 "CRITICAL", "JupyterLab"),
    ("/chroma",              "HIGH",     "ChromaDB vector store"),
    ("/qdrant",              "HIGH",     "Qdrant vector store"),
]

AI_CONFIG_KEYWORDS = [
    "openai_api_key", "anthropic_api_key", "huggingface_token",
    "model_endpoint", "llm_api_key", "llmConfig", "gpt-4", "gpt-3.5",
    "claude-", "gemini-", "llama-", "embeddingsEndpoint", "vectorStoreUrl",
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "AI_SECRET", "model_config",
]

def module_ai_misconfiguration(session, base_url, result, verbose):
    print(f"\n  {'─'*50}")
    print(f"  🤖  MODULE: AI Misconfiguration Exposure")
    print(f"  {'─'*50}")

    # 1. Endpoint probing
    for path, severity, label in AI_ENDPOINTS:
        url = urljoin(base_url, path)
        resp = safe_get(session, url, verbose)
        if not resp:
            continue
        result.urls_hit.append(url)

        if resp.status_code in (200, 201):
            result.findings.append(Finding(
                severity=severity,
                module="AI Misconfiguration",
                title=f"Open AI Endpoint: {path} ({label})",
                description=(
                    f"The AI endpoint '{path}' is publicly accessible without authentication. "
                    "Attackers can send arbitrary prompts, abuse API quota, or exfiltrate model data."
                ),
                evidence=f"HTTP {resp.status_code}\nBody: {resp.text[:250]}",
                recommendation=(
                    "Require authentication on all AI endpoints. "
                    "Add rate limiting, IP allowlisting, and input validation."
                ),
                url=url,
            ))
        elif resp.status_code in (401, 403):
            result.findings.append(Finding(
                severity="INFO",
                module="AI Misconfiguration",
                title=f"Protected AI Endpoint Exists: {path}",
                description="Endpoint exists but returns 401/403. Verify no bypass is possible.",
                evidence=f"HTTP {resp.status_code}",
                recommendation="Test for auth bypass. Ensure proper authentication is enforced.",
                url=url,
            ))
        time.sleep(0.05)

    # 2. JS keyword scanning
    home = safe_get(session, base_url, verbose)
    if home:
        js_srcs = re.findall(
            r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', home.text)
        for src in js_srcs[:15]:
            js_url = urljoin(base_url, src)
            js_resp = safe_get(session, js_url, verbose)
            if not js_resp or js_resp.status_code != 200:
                continue
            result.urls_hit.append(js_url)
            for kw in AI_CONFIG_KEYWORDS:
                if kw.lower() in js_resp.text.lower():
                    idx = js_resp.text.lower().find(kw.lower())
                    ctx = js_resp.text[max(0, idx-30):idx+80].strip()
                    result.findings.append(Finding(
                        severity="MEDIUM",
                        module="AI Misconfiguration",
                        title=f"AI Config Keyword in JS: '{kw}'",
                        description=(
                            f"Keyword '{kw}' found in client-side JavaScript, "
                            "potentially exposing AI model names, endpoints, or credentials."
                        ),
                        evidence=f"File: {js_url}\nContext: ...{ctx}...",
                        recommendation=(
                            "Move all AI config to server-side env variables. "
                            "Never expose model config in client-side code."
                        ),
                        url=js_url,
                    ))

    # 3. CORS check
    resp = safe_get(session, base_url, verbose)
    if resp:
        cors = resp.headers.get("Access-Control-Allow-Origin", "")
        if cors == "*":
            result.findings.append(Finding(
                severity="HIGH",
                module="AI Misconfiguration",
                title="Wildcard CORS on AI Service",
                description=(
                    "Access-Control-Allow-Origin: * allows any website to "
                    "make cross-origin requests. Enables CSRF-style prompt injection."
                ),
                evidence="Access-Control-Allow-Origin: *",
                recommendation="Restrict CORS to specific trusted origins.",
                url=base_url,
            ))

    # 4. Error disclosure via POST
    for path, payload in [
        ("/v1/chat/completions", {"model": "x", "messages": []}),
        ("/api/generate", {"prompt": "test"}),
        ("/api/ai/query", {"query": "test"}),
    ]:
        url = urljoin(base_url, path)
        resp = safe_post(session, url, payload, verbose)
        if not resp:
            continue
        result.urls_hit.append(url)
        body = resp.text[:500]
        leak_terms = [t for t in [
            "openai", "langchain", "transformers", "torch",
            "tensorflow", "traceback", "Exception", "api_key"
        ] if t.lower() in body.lower()]
        if leak_terms and resp.status_code in (400, 422, 500):
            result.findings.append(Finding(
                severity="HIGH",
                module="AI Misconfiguration",
                title="AI Framework Details in Error Response",
                description=(
                    "Error responses leak internal AI library/framework names, "
                    "aiding targeted exploitation."
                ),
                evidence=f"URL: {url}\nHTTP {resp.status_code}\nLeaked: {leak_terms}\nBody: {body}",
                recommendation="Return generic error messages. Log details server-side only.",
                url=url,
            ))
        time.sleep(0.1)

# ══════════════════════════════════════════════
#  Report
# ══════════════════════════════════════════════

def print_banner():
    print(f"""
{BOLD}╔══════════════════════════════════════════════════════════════╗
║           FORTIS - Vulnerability Scanner Suite               ║
║  Modules: AI Misconfiguration | Cloud Keys | JWT | Files     ║
╚══════════════════════════════════════════════════════════════╝{RESET}""")


def print_report(result: ScanResult):
    from collections import Counter
    print(f"\n{'═'*65}")
    print(f"  {BOLD}SCAN REPORT{RESET}")
    print(f"  Target   : {result.target}")
    print(f"  URLs Hit : {len(result.urls_hit)}")
    print(f"  Findings : {len(result.findings)}")
    print(f"{'═'*65}")

    if not result.findings:
        print(f"\n  ✅  {BOLD}No vulnerabilities detected!{RESET}\n")
        return

    sorted_f = sorted(result.findings,
                      key=lambda f: SEVERITY_ORDER.get(f.severity, 9))

    counts = Counter(f.severity for f in sorted_f)
    print(f"\n  {BOLD}SUMMARY BY SEVERITY{RESET}")
    print(f"  {'─'*40}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if counts[sev]:
            c = SEVERITY_COLORS[sev]
            bar = "█" * min(counts[sev], 30)
            print(f"  {c}{sev:<10}{RESET} {counts[sev]:>3}  {c}{bar}{RESET}")

    # Group by module
    modules = {}
    for f in sorted_f:
        modules.setdefault(f.module, []).append(f)

    print(f"\n  {BOLD}SUMMARY BY MODULE{RESET}")
    print(f"  {'─'*40}")
    for mod, findings in modules.items():
        c_counts = Counter(f.severity for f in findings)
        sev_str = " | ".join(
            f"{SEVERITY_COLORS[s]}{s}: {c_counts[s]}{RESET}"
            for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            if c_counts[s]
        )
        print(f"  {BOLD}{mod}{RESET} ({len(findings)} findings) → {sev_str}")

    print(f"\n  {BOLD}DETAILED FINDINGS{RESET}")
    for i, f in enumerate(sorted_f, 1):
        c = SEVERITY_COLORS.get(f.severity, "")
        print(f"\n  ┌─ Finding #{i}  [{f.module}]")
        print(f"  │  {BOLD}Severity{RESET}     : {c}{f.severity}{RESET}")
        print(f"  │  {BOLD}Title{RESET}        : {f.title}")
        print(f"  │  {BOLD}URL{RESET}          : {f.url}")
        print(f"  │  {BOLD}Description{RESET}  : {f.description}")
        if f.evidence:
            lines = f.evidence.splitlines()
            print(f"  │  {BOLD}Evidence{RESET}     : {lines[0]}")
            for ln in lines[1:]:
                print(f"  │               {ln}")
        print(f"  │  {BOLD}Fix{RESET}          : {f.recommendation}")
        print(f"  └{'─'*58}")

    if result.errors:
        print(f"\n  {BOLD}ERRORS DURING SCAN{RESET}")
        for e in result.errors:
            print(f"  ⚠  {e}")


def save_json(result: ScanResult, path: str):
    data = {
        "target": result.target,
        "total_findings": len(result.findings),
        "urls_scanned": len(result.urls_hit),
        "findings": [
            {
                "severity":       f.severity,
                "module":         f.module,
                "title":          f.title,
                "url":            f.url,
                "description":    f.description,
                "evidence":       f.evidence,
                "recommendation": f.recommendation,
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

MODULES = {
    "cloud": ("Cloud/API Key Exposure", module_cloud_keys),
    "jwt":   ("JWT Security",           module_jwt),
    "files": ("Sensitive File Exposure", module_sensitive_files),
    "ai":    ("AI Misconfiguration",    module_ai_misconfiguration),
}

def main():
    parser = argparse.ArgumentParser(
        description="FORTIS - Unified Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python fortis_scanner.py --url http://localhost:5000
  python fortis_scanner.py --url https://example.com --verbose
  python fortis_scanner.py --url https://example.com --output report.json
  python fortis_scanner.py --url https://example.com --modules ai jwt
        """,
    )
    parser.add_argument("--url",     required=True, help="Target URL")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--output",  "-o", default="", help="Save JSON report")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument(
        "--modules", nargs="+",
        choices=list(MODULES.keys()),
        default=list(MODULES.keys()),
        help="Modules to run (default: all). Choices: cloud jwt files ai"
    )
    args = parser.parse_args()

    target = args.url.strip()
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    parsed   = urlparse(target)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    print_banner()
    print(f"\n  Target  : {BOLD}{base_url}{RESET}")
    print(f"  Modules : {', '.join(args.modules)}")
    print(f"  Timeout : {args.timeout}s\n")

    session = build_session(args.timeout)
    result  = ScanResult(target=base_url)

    for key in args.modules:
        label, fn = MODULES[key]
        try:
            fn(session, base_url, result, args.verbose)
        except Exception as e:
            result.errors.append(f"{label}: {e}")

    print_report(result)

    if args.output:
        save_json(result, args.output)


if __name__ == "__main__":
    main()