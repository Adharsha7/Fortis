"""
AI Misconfiguration Exposure Detector
=======================================
Detects exposed AI/ML endpoints, API keys, model configurations,
and insecure AI integrations on a target website.

Usage:
    python ai_misconfiguration_detector.py --url https://example.com
    python ai_misconfiguration_detector.py --url https://example.com --verbose
"""

import argparse
import json
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ─────────────────────────────────────────────
#  Data structures
# ─────────────────────────────────────────────

@dataclass
class Finding:
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW | INFO
    category: str
    title: str
    description: str
    evidence: str = ""
    recommendation: str = ""
    url: str = ""

@dataclass
class ScanResult:
    target: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scanned_urls: list[str] = field(default_factory=list)

# ─────────────────────────────────────────────
#  Constants – patterns & paths
# ─────────────────────────────────────────────

# Exposed AI API key patterns
API_KEY_PATTERNS = {
    "OpenAI API Key":        r'sk-[A-Za-z0-9]{20,}',
    "OpenAI Org ID":         r'org-[A-Za-z0-9]{24,}',
    "Anthropic API Key":     r'sk-ant-[A-Za-z0-9\-_]{50,}',
    "HuggingFace Token":     r'hf_[A-Za-z0-9]{30,}',
    "Cohere API Key":        r'[A-Za-z0-9]{40}',          # generic fallback
    "Replicate Token":       r'r8_[A-Za-z0-9]{35,}',
    "Google AI Key":         r'AIza[0-9A-Za-z\-_]{35}',
    "AWS Bedrock Key":       r'(?:AKIA|ASIA)[0-9A-Z]{16}',
    "Azure OpenAI Key":      r'[0-9a-f]{32}',
}

# Sensitive AI config keywords found in JS/HTML
CONFIG_KEYWORDS = [
    "openai_api_key", "anthropic_api_key", "huggingface_token",
    "model_endpoint", "inference_endpoint", "llm_api_key",
    "gpt-4", "gpt-3.5", "claude-", "gemini-", "llama-",
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "AI_SECRET",
    "ai_model_config", "model_config", "llmConfig",
    "embeddingsEndpoint", "vectorStoreUrl",
]

# Common exposed AI endpoint paths
AI_ENDPOINT_PATHS = [
    # OpenAI-compatible
    "/v1/chat/completions",
    "/v1/completions",
    "/v1/embeddings",
    "/v1/models",
    "/api/chat",
    "/api/completion",
    "/api/generate",
    # HuggingFace / custom inference
    "/inference",
    "/predict",
    "/infer",
    # LangChain / LlamaIndex
    "/langchain/query",
    "/llm/query",
    "/rag/query",
    "/chain/run",
    # Admin / debug panels
    "/ai/admin",
    "/ai/debug",
    "/ai/config",
    "/ai/logs",
    "/api/ai/settings",
    # Vector DBs
    "/qdrant",
    "/weaviate",
    "/pinecone",
    "/chroma",
    "/milvus",
    # Model management
    "/mlflow",
    "/mlflow/api",
    "/api/v2/mlflow",
    "/seldon",
    "/triton/v2",
    "/torchserve",
    # Jupyter / notebooks (often exposed)
    "/jupyter",
    "/notebook",
    "/lab",
    "/tree",
    # Prometheus / metrics (can leak model info)
    "/metrics",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    # Misc AI config files
    "/.env",
    "/config.json",
    "/ai_config.json",
    "/model_config.json",
    "/settings.json",
    "/api/keys",
]

# Headers that reveal AI infrastructure
REVEALING_HEADERS = [
    "x-openai-model", "x-model", "x-ai-model",
    "x-inference-backend", "x-llm-provider",
    "x-ray-traced-id",        # AWS Bedrock
    "openai-organization",
    "x-ratelimit-requests-openai",
]

# JS files to fetch and inspect
JS_PATTERNS = [
    r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']',
    r'<script[^>]+src=["\']([^"\']+chunk[^"\']*)["\']',
]

# ─────────────────────────────────────────────
#  HTTP session helper
# ─────────────────────────────────────────────

def build_session(timeout: int = 10) -> requests.Session:
    session = requests.Session()
    retry = Retry(total=2, backoff_factor=0.3,
                  status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (SecurityScanner/1.0; VulnResearch)",
        "Accept": "text/html,application/json,*/*",
    })
    session.timeout = timeout
    return session


def safe_get(session: requests.Session, url: str,
             verbose: bool = False) -> Optional[requests.Response]:
    try:
        r = session.get(url, timeout=session.timeout,
                        allow_redirects=True, verify=False)
        if verbose:
            print(f"  [{r.status_code}] {url}")
        return r
    except Exception as e:
        if verbose:
            print(f"  [ERR] {url} → {e}")
        return None

# ─────────────────────────────────────────────
#  Check modules
# ─────────────────────────────────────────────

def check_exposed_endpoints(session, base_url, result, verbose):
    """Probe known AI endpoint paths for open access."""
    print("[*] Checking exposed AI endpoints...")
    for path in AI_ENDPOINT_PATHS:
        url = urljoin(base_url, path)
        resp = safe_get(session, url, verbose)
        if resp is None:
            continue

        result.scanned_urls.append(url)

        # 200 / 201 = likely exposed
        if resp.status_code in (200, 201):
            ct = resp.headers.get("Content-Type", "")
            body_preview = resp.text[:300]

            severity = "HIGH"
            desc = f"AI endpoint is publicly accessible without authentication."

            # Upgrade severity for particularly dangerous endpoints
            if any(k in path for k in ["/v1/chat", "/v1/completions",
                                        "/api/generate", "/chain/run"]):
                severity = "CRITICAL"
                desc = ("Unauthenticated LLM inference endpoint detected. "
                        "Attackers can send arbitrary prompts, abuse quota, "
                        "and potentially exfiltrate training data.")

            if any(k in path for k in ["/.env", "/api/keys", "/ai/config"]):
                severity = "CRITICAL"
                desc = "Sensitive AI configuration file/endpoint is publicly readable."

            result.findings.append(Finding(
                severity=severity,
                category="Exposed AI Endpoint",
                title=f"Open AI Endpoint: {path}",
                description=desc,
                evidence=f"HTTP {resp.status_code} | Content-Type: {ct}\nBody: {body_preview}",
                recommendation=(
                    "Restrict endpoint access with authentication (API keys / OAuth). "
                    "Place behind a reverse proxy with rate-limiting and IP allowlisting."
                ),
                url=url,
            ))

        # 401/403 = protected but endpoint exists (info)
        elif resp.status_code in (401, 403):
            result.findings.append(Finding(
                severity="INFO",
                category="Exposed AI Endpoint",
                title=f"Protected AI Endpoint Found: {path}",
                description="Endpoint exists but requires authentication.",
                evidence=f"HTTP {resp.status_code}",
                recommendation="Verify authentication is properly enforced; check for bypass vectors.",
                url=url,
            ))

        time.sleep(0.1)   # polite delay


def check_response_headers(session, base_url, result, verbose):
    """Look for AI-revealing or misconfigured response headers."""
    print("[*] Checking response headers...")
    resp = safe_get(session, base_url, verbose)
    if resp is None:
        return

    headers = {k.lower(): v for k, v in resp.headers.items()}

    for h in REVEALING_HEADERS:
        if h in headers:
            result.findings.append(Finding(
                severity="MEDIUM",
                category="Information Disclosure",
                title=f"AI Infrastructure Header Exposed: {h}",
                description=(
                    f"Response header '{h}: {headers[h]}' reveals the AI "
                    "backend in use, aiding targeted attacks."
                ),
                evidence=f"{h}: {headers[h]}",
                recommendation="Strip internal AI headers at the reverse-proxy layer.",
                url=base_url,
            ))

    # Check CORS for AI endpoints
    if "access-control-allow-origin" in headers:
        if headers["access-control-allow-origin"] == "*":
            result.findings.append(Finding(
                severity="HIGH",
                category="CORS Misconfiguration",
                title="Wildcard CORS on AI Service",
                description=(
                    "Access-Control-Allow-Origin: * allows any website to make "
                    "cross-origin requests to this AI service, enabling CSRF-style "
                    "prompt injection or credential theft."
                ),
                evidence="Access-Control-Allow-Origin: *",
                recommendation="Restrict CORS to trusted origins only.",
                url=base_url,
            ))

    # Missing security headers
    missing = []
    for h in ["x-content-type-options", "x-frame-options",
              "content-security-policy"]:
        if h not in headers:
            missing.append(h)
    if missing:
        result.findings.append(Finding(
            severity="LOW",
            category="Missing Security Headers",
            title="Missing HTTP Security Headers",
            description=f"Headers absent: {', '.join(missing)}",
            evidence="",
            recommendation="Add recommended security headers to all responses.",
            url=base_url,
        ))


def check_js_files(session, base_url, result, verbose):
    """Fetch homepage JS files and scan for leaked keys/configs."""
    print("[*] Scanning JavaScript files for leaked AI credentials...")
    resp = safe_get(session, base_url, verbose)
    if resp is None:
        return

    # Collect JS URLs from HTML
    js_urls = set()
    for pattern in JS_PATTERNS:
        for match in re.findall(pattern, resp.text, re.IGNORECASE):
            js_urls.add(urljoin(base_url, match))

    # Also try common bundle names
    for name in ["main.js", "bundle.js", "app.js", "index.js",
                 "vendor.js", "chunk.js", "runtime.js"]:
        js_urls.add(urljoin(base_url, f"/static/js/{name}"))
        js_urls.add(urljoin(base_url, f"/assets/{name}"))

    for js_url in list(js_urls)[:20]:   # cap at 20 files
        js_resp = safe_get(session, js_url, verbose)
        if js_resp is None or js_resp.status_code != 200:
            continue
        result.scanned_urls.append(js_url)
        content = js_resp.text

        # Key pattern search
        for key_name, pattern in API_KEY_PATTERNS.items():
            matches = re.findall(pattern, content)
            for match in matches:
                # Filter obvious false positives
                if len(set(match)) < 5:
                    continue
                result.findings.append(Finding(
                    severity="CRITICAL",
                    category="Hardcoded API Key",
                    title=f"Hardcoded {key_name} Found in JS",
                    description=(
                        f"An {key_name} was detected in a publicly accessible "
                        "JavaScript file. Attackers can use this key to incur "
                        "costs, exfiltrate data, or abuse the AI service."
                    ),
                    evidence=f"File: {js_url}\nMatch: {match[:12]}...{match[-4:]}",
                    recommendation=(
                        "Remove all API keys from client-side code. "
                        "Proxy AI requests through your backend. "
                        "Rotate the exposed key immediately."
                    ),
                    url=js_url,
                ))

        # Config keyword search
        for keyword in CONFIG_KEYWORDS:
            if keyword.lower() in content.lower():
                # Extract surrounding context
                idx = content.lower().find(keyword.lower())
                snippet = content[max(0, idx - 40): idx + 80].strip()
                result.findings.append(Finding(
                    severity="MEDIUM",
                    category="AI Config Disclosure",
                    title=f"AI Configuration Keyword in JS: '{keyword}'",
                    description=(
                        f"The keyword '{keyword}' was found in a JS file, "
                        "potentially revealing AI model names, endpoints, or settings."
                    ),
                    evidence=f"File: {js_url}\nContext: ...{snippet}...",
                    recommendation=(
                        "Move AI configuration to server-side environment variables. "
                        "Never expose model names or endpoints in client code."
                    ),
                    url=js_url,
                ))
        time.sleep(0.05)


def check_robots_sitemap(session, base_url, result, verbose):
    """Check robots.txt and sitemap for AI-related path disclosures."""
    print("[*] Checking robots.txt and sitemap...")
    for path in ["/robots.txt", "/sitemap.xml"]:
        url = urljoin(base_url, path)
        resp = safe_get(session, url, verbose)
        if resp is None or resp.status_code != 200:
            continue
        result.scanned_urls.append(url)
        content = resp.text.lower()
        ai_refs = [kw for kw in [
            "ai", "ml", "model", "llm", "gpt", "claude",
            "inference", "embedding", "vector", "rag",
        ] if kw in content]
        if ai_refs:
            result.findings.append(Finding(
                severity="LOW",
                category="Information Disclosure",
                title=f"AI-Related Paths in {path}",
                description=(
                    f"{path} references AI-related paths/keywords: {ai_refs}. "
                    "This can help attackers map the AI attack surface."
                ),
                evidence=resp.text[:400],
                recommendation=f"Review {path} and remove sensitive path disclosures.",
                url=url,
            ))


def check_error_disclosure(session, base_url, result, verbose):
    """Trigger error conditions and look for AI stack traces."""
    print("[*] Probing for AI error disclosure...")
    probes = [
        ("/v1/chat/completions", {"model": "x", "messages": []}),
        ("/api/ai/query", {"query": "test"}),
        ("/api/generate", {"prompt": "test"}),
    ]
    for path, payload in probes:
        url = urljoin(base_url, path)
        try:
            resp = session.post(url, json=payload, timeout=8, verify=False)
            result.scanned_urls.append(url)
            body = resp.text[:600]
            # Look for AI-related stack trace keywords
            leak_indicators = [
                "openai", "anthropic", "langchain", "llamaindex",
                "transformers", "torch", "tensorflow", "huggingface",
                "traceback", "stacktrace", "Exception", "InternalServerError",
                "api_key", "token", "secret",
            ]
            found = [k for k in leak_indicators if k.lower() in body.lower()]
            if found and resp.status_code in (400, 422, 500):
                result.findings.append(Finding(
                    severity="HIGH",
                    category="Error Disclosure",
                    title=f"AI Stack Trace / Internal Details in Error Response",
                    description=(
                        "Error responses leak internal AI framework details, "
                        "library names, or configuration that aids targeted exploitation."
                    ),
                    evidence=f"URL: {url}\nHTTP {resp.status_code}\nLeaked: {found}\nBody: {body}",
                    recommendation=(
                        "Implement generic error messages for all AI endpoints. "
                        "Log detailed errors server-side only."
                    ),
                    url=url,
                ))
        except Exception:
            pass
        time.sleep(0.1)


def check_prompt_injection_surface(session, base_url, result, verbose):
    """Check if public-facing AI chat/input surfaces exist (attack surface only)."""
    print("[*] Identifying prompt injection attack surfaces...")
    surface_paths = [
        "/chat", "/chatbot", "/assistant", "/ai-chat",
        "/support/chat", "/help/ai", "/ask", "/query",
    ]
    for path in surface_paths:
        url = urljoin(base_url, path)
        resp = safe_get(session, url, verbose)
        if resp is None:
            continue
        result.scanned_urls.append(url)
        if resp.status_code == 200:
            body = resp.text.lower()
            if any(k in body for k in ["chat", "message", "ask", "send", "prompt"]):
                result.findings.append(Finding(
                    severity="MEDIUM",
                    category="Prompt Injection Surface",
                    title=f"Public AI Chat Interface Found: {path}",
                    description=(
                        "A public AI chat/query interface was detected. "
                        "These surfaces are prone to prompt injection, jailbreaking, "
                        "and indirect prompt injection via user-controlled content."
                    ),
                    evidence=f"HTTP 200 at {url}",
                    recommendation=(
                        "Implement input sanitization and output filtering. "
                        "Use system prompt hardening and content policy enforcement. "
                        "Apply rate limiting per user/session."
                    ),
                    url=url,
                ))
        time.sleep(0.05)

# ─────────────────────────────────────────────
#  Reporter
# ─────────────────────────────────────────────

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",   # red
    "HIGH":     "\033[93m",   # yellow
    "MEDIUM":   "\033[94m",   # blue
    "LOW":      "\033[96m",   # cyan
    "INFO":     "\033[37m",   # white
}
RESET = "\033[0m"


def print_report(result: ScanResult):
    print("\n" + "=" * 65)
    print(f"  AI MISCONFIGURATION EXPOSURE REPORT")
    print(f"  Target : {result.target}")
    print(f"  URLs   : {len(result.scanned_urls)} scanned")
    print("=" * 65)

    if not result.findings:
        print("\n  ✅  No AI misconfiguration vulnerabilities detected.\n")
        return

    sorted_findings = sorted(result.findings,
                             key=lambda f: SEVERITY_ORDER.get(f.severity, 9))

    # Summary table
    from collections import Counter
    counts = Counter(f.severity for f in sorted_findings)
    print("\n  SUMMARY")
    print("  " + "-" * 40)
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if counts[sev]:
            color = SEVERITY_COLORS[sev]
            print(f"  {color}{sev:<10}{RESET} {counts[sev]}")
    print()

    # Detailed findings
    for i, f in enumerate(sorted_findings, 1):
        color = SEVERITY_COLORS.get(f.severity, "")
        print(f"  ┌─ Finding #{i}")
        print(f"  │  Severity  : {color}{f.severity}{RESET}")
        print(f"  │  Category  : {f.category}")
        print(f"  │  Title     : {f.title}")
        print(f"  │  URL       : {f.url}")
        print(f"  │  Details   : {f.description}")
        if f.evidence:
            ev_lines = f.evidence.splitlines()
            print(f"  │  Evidence  : {ev_lines[0]}")
            for line in ev_lines[1:]:
                print(f"  │             {line}")
        print(f"  │  Fix       : {f.recommendation}")
        print(f"  └{'─' * 55}")
        print()


def save_json_report(result: ScanResult, path: str):
    data = {
        "target": result.target,
        "total_findings": len(result.findings),
        "scanned_urls": result.scanned_urls,
        "findings": [
            {
                "severity": f.severity,
                "category": f.category,
                "title": f.title,
                "url": f.url,
                "description": f.description,
                "evidence": f.evidence,
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

# ─────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="AI Misconfiguration Exposure Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ai_misconfiguration_detector.py --url https://example.com
  python ai_misconfiguration_detector.py --url https://example.com --verbose --output report.json
        """,
    )
    parser.add_argument("--url", required=True, help="Target website URL")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show each HTTP request")
    parser.add_argument("--output", "-o", default="",
                        help="Save JSON report to file (optional)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Request timeout in seconds (default: 10)")
    args = parser.parse_args()

    # Normalise URL
    target = args.url.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    parsed = urlparse(target)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    print(f"\n{'=' * 65}")
    print(f"  AI MISCONFIGURATION EXPOSURE DETECTOR")
    print(f"  Target: {base_url}")
    print(f"{'=' * 65}\n")

    # Suppress InsecureRequestWarning
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    session = build_session(timeout=args.timeout)
    result  = ScanResult(target=base_url)

    checks = [
        check_exposed_endpoints,
        check_response_headers,
        check_js_files,
        check_robots_sitemap,
        check_error_disclosure,
        check_prompt_injection_surface,
    ]

    for check in checks:
        try:
            check(session, base_url, result, args.verbose)
        except Exception as e:
            result.errors.append(f"{check.__name__}: {e}")
            if args.verbose:
                print(f"  [!] Error in {check.__name__}: {e}")

    print_report(result)

    if args.output:
        save_json_report(result, args.output)


if __name__ == "__main__":
    main()