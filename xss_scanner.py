
from __future__ import annotations
import asyncio
import hashlib
import logging
import re
from dataclasses import dataclass, field
from html import unescape
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger("fortis.xss_scanner")

# ---------------------------------------------------------------------------
# DOM Sinks — grouped by risk
# ---------------------------------------------------------------------------

_CRITICAL_SINKS: List[Tuple[str, re.Pattern]] = [
    ("innerHTML",           re.compile(r'\.innerHTML\s*[+]?=',                    re.I)),
    ("outerHTML",           re.compile(r'\.outerHTML\s*[+]?=',                    re.I)),
    ("document.write",      re.compile(r'document\.write(?:ln)?\s*\(',             re.I)),
    ("eval",                re.compile(r'\beval\s*\(',                              re.I)),
    ("setTimeout(string)",  re.compile(r'setTimeout\s*\(\s*(?:`|["\'])',            re.I)),
    ("setInterval(string)", re.compile(r'setInterval\s*\(\s*(?:`|["\'])',           re.I)),
    ("insertAdjacentHTML",  re.compile(r'\.insertAdjacentHTML\s*\(',                re.I)),
    ("setAttribute-src",    re.compile(r'\.setAttribute\s*\(\s*["\'](?:src|href|action)["\']', re.I)),
    ("iframe-srcdoc",       re.compile(r'\bsrcdoc\s*=',                             re.I)),
    ("javascript-url",      re.compile(r'''(?:src|href|action)\s*=\s*['"]?javascript:''', re.I)),
    ("Function-constructor",re.compile(r'\bnew\s+Function\s*\(',                    re.I)),
    ("execScript",          re.compile(r'\bexecScript\s*\(',                        re.I)),
    ("document.domain",     re.compile(r'document\.domain\s*=',                     re.I)),
    ("location.href-assign",re.compile(r'(?:location\.href|window\.location)\s*=\s*(?!["\'/])', re.I)),
]

_HIGH_SINKS: List[Tuple[str, re.Pattern]] = [
    ("postMessage-send",         re.compile(r'\.postMessage\s*\(',              re.I)),
    ("createContextualFragment", re.compile(r'createContextualFragment\s*\(',  re.I)),
    ("importNode",               re.compile(r'document\.importNode\s*\(',       re.I)),
    ("write-target",             re.compile(r'\bwindow\.location\b(?!\.href\s*=\s*["\'/])', re.I)),
]

# ---------------------------------------------------------------------------
# Framework-specific unsafe patterns — detect misuse, not mere presence
# ---------------------------------------------------------------------------

# React: detect dangerouslySetInnerHTML with a non-constant __html value
_REACT_DANGEROUS_RE = re.compile(
    r'dangerouslySetInnerHTML\s*=\s*\{\s*\{?\s*__html\s*:\s*(?![\s]*["\'])',
    re.I,
)
# Angular: bypassSecurityTrust — any variant
_ANGULAR_BYPASS_RE = re.compile(
    r'bypassSecurityTrust(?:Html|Url|ResourceUrl|Script|Style)\s*\(',
    re.I,
)
# Angular innerHTML binding with dynamic (non-quoted) expression
_ANGULAR_INNERHTML_RE = re.compile(r'\[innerHTML\]\s*=\s*"[^"]*\b(?![\'"]\s*\+)', re.I)
# Vue v-html with a bound variable (not a static string)
_VUE_VHTML_RE = re.compile(r'\bv-html\s*=\s*["\'][^"\']*\b(?!\s*["\'])', re.I)
# Next.js SSR dangerous usage: __NEXT_DATA__ or getServerSideProps + dangerouslySetInnerHTML
_NEXTJS_DANGEROUS_RE = re.compile(
    r'dangerouslySetInnerHTML[\s\S]{0,400}?(?:__NEXT_DATA__|getServerSideProps|'
    r'INITIAL_STATE|initialData)',
    re.I,
)

_FRAMEWORK_SINKS: List[Tuple[str, str, re.Pattern]] = [
    ("React",    "dangerouslySetInnerHTML with dynamic __html",  _REACT_DANGEROUS_RE),
    ("Angular",  "bypassSecurityTrust* call",                    _ANGULAR_BYPASS_RE),
    ("Angular",  "[innerHTML] dynamic binding",                  _ANGULAR_INNERHTML_RE),
    ("Vue",      "v-html with bound variable",                   _VUE_VHTML_RE),
    ("Next.js",  "dangerouslySetInnerHTML near SSR data source", _NEXTJS_DANGEROUS_RE),
]

# ---------------------------------------------------------------------------
# Tainted sources
# ---------------------------------------------------------------------------

_SOURCE_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("location.search",   re.compile(r'\blocation\.search\b',              re.I)),
    ("location.hash",     re.compile(r'\blocation\.hash\b',                re.I)),
    ("location.href",     re.compile(r'\blocation\.href\b',                re.I)),
    ("document.URL",      re.compile(r'\bdocument\.URL\b',                 re.I)),
    ("document.referrer", re.compile(r'\bdocument\.referrer\b',            re.I)),
    ("document.cookie",   re.compile(r'\bdocument\.cookie\b',              re.I)),
    ("window.name",       re.compile(r'\bwindow\.name\b',                  re.I)),
    ("postMessage recv",  re.compile(r'''addEventListener\s*\(\s*['"]message['"]''', re.I)),
    ("URLSearchParams",   re.compile(r'\bURLSearchParams\b',               re.I)),
    ("history.state",     re.compile(r'\bhistory\.state\b',                re.I)),
    ("input.value",       re.compile(r'\.value\b',                         re.I)),
]

# ---------------------------------------------------------------------------
# Inline event handlers — corrected regex (no broken character class)
# ---------------------------------------------------------------------------

_EVENT_NAMES_JOINED = (
    "onclick|ondblclick|onerror|onload|onmouseover|onmouseout|onkeydown|onkeyup"
    "|onkeypress|onsubmit|onchange|onfocus|onblur|oninput|onpaste|ondrag|ondrop"
    "|oncontextmenu|onpointerdown|onpointerup|ontouchstart|ontouchend|onanimationend"
    "|ontransitionend|onscroll|onwheel|onmouseenter|onmouseleave|onbeforeunload"
    "|onhashchange|onmessage|onresize|onstorage"
)

# Match: <tag ... eventname="handler" ...>
# handler must be ≥ 5 characters; captured in group 3
_INLINE_EVENT_RE = re.compile(
    rf'<[^>]{{1,2000}}\s({_EVENT_NAMES_JOINED})\s*=\s*'
    r'(?:"([^"]{5,}?)"|\'([^\']{5,}?)\')',
    re.I,
)

# ---------------------------------------------------------------------------
# CSP detection
# ---------------------------------------------------------------------------

_CSP_META_RE = re.compile(
    r'<meta[^>]+http-equiv\s*=\s*["\']Content-Security-Policy["\'][^>]+'
    r'content\s*=\s*["\']([^"\']+)',
    re.I,
)
_CSP_HEADER_MARKER = "content-security-policy"

# Each weakness: (label, test_fn)
# test_fn(csp_value: str) -> bool
def _csp_has_unsafe_inline(v: str) -> bool:
    return "'unsafe-inline'" in v.lower() and _csp_applies_to_scripts(v)

def _csp_has_unsafe_eval(v: str) -> bool:
    return "'unsafe-eval'" in v.lower()

def _csp_has_wildcard(v: str) -> bool:
    return bool(re.search(r"(?:script-src|default-src)[^;]*\s\*", v, re.I))

def _csp_has_data_uri(v: str) -> bool:
    return "'data:'" in v.lower()

def _csp_has_http_source(v: str) -> bool:
    # http: as a source scheme (not inside a URL like http://example.com)
    return bool(re.search(r"(?:^|[\s;])http:(?!\S)", v, re.I))

def _csp_missing_default_src(v: str) -> bool:
    vl = v.lower()
    return "default-src" not in vl and "script-src" not in vl

def _csp_applies_to_scripts(v: str) -> bool:
    """True when unsafe-inline applies to scripts (not just style)."""
    vl = v.lower()
    # If script-src exists, unsafe-inline must be in it; else check default-src
    script_match = re.search(r'script-src([^;]*)', vl)
    if script_match:
        return "'unsafe-inline'" in script_match.group(1)
    default_match = re.search(r'default-src([^;]*)', vl)
    if default_match:
        return "'unsafe-inline'" in default_match.group(1)
    return False

_CSP_WEAKNESS_CHECKS: List[Tuple[str, Any]] = [
    ("unsafe-inline script-src",  _csp_has_unsafe_inline),
    ("unsafe-eval",               _csp_has_unsafe_eval),
    ("wildcard source (*)",       _csp_has_wildcard),
    ("data: URI source",          _csp_has_data_uri),
    ("http: source scheme",       _csp_has_http_source),
    ("missing default-src and script-src", _csp_missing_default_src),
]

_CSP_BYPASS_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("JSONP callback injection",
     re.compile(r'[?&]callback\s*=\s*(?:alert|confirm|prompt|eval)\b', re.I)),
    ("AngularJS template injection via ng-app",
     re.compile(r'ng-app[^>]*>\s*\{\{[^}]{1,200}\}\}', re.I | re.S)),
    ("base-uri not restricted (base tag present)",
     re.compile(r'<base\s[^>]*href\s*=', re.I)),
    ("AngularJS sandbox escape",
     re.compile(r'\$\$\s*\.proto|\bconstructor\s*\[', re.I)),
    ("script-src nonce with unsafe-inline fallback",
     re.compile(r"'nonce-[^']+'\s+'unsafe-inline'", re.I)),
]

# ---------------------------------------------------------------------------
# Template injection patterns — with false-positive guards
# ---------------------------------------------------------------------------

# Patterns that indicate legitimate framework usage (not injection risk)
_TEMPLATE_FP_GUARDS: List[re.Pattern] = [
    re.compile(r'ng-(?:if|for|model|bind|repeat|switch)\s*=\s*"', re.I),   # Angular directives
    re.compile(r':(?:class|style|for|if|key|ref)\s*=\s*"',         re.I),   # Vue v-bind
    re.compile(r'<template\b',                                       re.I),   # HTML template tag
]

_TEMPLATE_PATTERNS: List[Tuple[str, re.Pattern, Optional[re.Pattern]]] = [
    # (name, detection_pattern, benign_guard_pattern)
    ("Mustache/Handlebars {{ }}",
     re.compile(r'\{\{\s*[a-zA-Z_$][a-zA-Z0-9_.()[\]|"\']{2,60}\s*\}\}', re.I),
     re.compile(r'(?:ng-app|ng-controller|v-app|x-ng-app)', re.I)),
    ("JS template literal ${...} in HTML",
     re.compile(r'\$\{[a-zA-Z_$][a-zA-Z0-9_.()[\]|"\']{1,60}\}', re.I),
     None),
    ("ERB/EJS <%...%>",
     re.compile(r'<%[=\-]?\s*[a-zA-Z_$][^%]{0,60}%>', re.I),
     None),
    ("Twig/Jinja2 {% %}",
     re.compile(r'\{%\s*(?:if|for|block|extends|include|set|macro|call|filter|raw)\b', re.I),
     None),
    ("SSTI probe pattern",
     re.compile(r'\{\{7\*7\}\}|\$\{7\*7\}|<%=7\*7%>', re.I),
     None),
]

# ---------------------------------------------------------------------------
# Stored XSS — persistent flow indicators
# ---------------------------------------------------------------------------

# Surface detection
_STORED_SURFACE_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("comment/message field",
     re.compile(
         r'<(?:textarea|input)[^>]+(?:name|id)\s*=\s*["\']'
         r'(?:comment|message|body|content|text|reply|post|note)["\']',
         re.I,
     )),
    ("profile/bio field",
     re.compile(
         r'<(?:textarea|input)[^>]+(?:name|id)\s*=\s*["\']'
         r'(?:bio|about|description|profile|username|name|display_name)["\']',
         re.I,
     )),
    ("search box",
     re.compile(
         r'<input[^>]+(?:name|id)\s*=\s*["\'](?:q|query|search|s|keyword|term)["\']',
         re.I,
     )),
    ("rich text editor",
     re.compile(r'(?:tinymce|quill|ckeditor|summernote|froala|ace\.edit|prosemirror)', re.I)),
    ("file upload field",
     re.compile(r'<input[^>]+type\s*=\s*["\']file["\']', re.I)),
]

# Persistent flow indicators: evidence that content is stored/retrieved from backend
_STORED_FLOW_INDICATORS: List[re.Pattern] = [
    re.compile(r'(?:api|ajax|fetch|xhr)\s*(?:\.|\.open\s*\(|\.get\s*\(|\.post\s*\()', re.I),
    re.compile(r'(?:localStorage|sessionStorage|indexedDB)\.(?:setItem|getItem)', re.I),
    re.compile(r'(?:INSERT\s+INTO|UPDATE\s+\w+\s+SET)', re.I),
    re.compile(r'<(?:form)[^>]+action\s*=\s*["\'][^"\']+["\']', re.I),
    re.compile(r'(?:ws://|wss://)', re.I),
    re.compile(r'socket\.(?:emit|send|on)\b', re.I),
]

# ---------------------------------------------------------------------------
# Sanitization detection — used to modulate confidence, not suppress findings
# ---------------------------------------------------------------------------

_SANITIZERS: List[Tuple[str, re.Pattern]] = [
    ("DOMPurify",          re.compile(r'\bDOMPurify\.sanitize\s*\(', re.I)),
    ("sanitize-html",      re.compile(r'\bsanitizeHtml\s*\(',         re.I)),
    ("xss-filters",        re.compile(r'\bxssFilters\.',              re.I)),
    ("he/entities encode", re.compile(r'\bhe\.encode|entities\.encode', re.I)),
    ("Angular sanitizer",  re.compile(r'\bDomSanitizer\.sanitize\s*\(', re.I)),
    ("textContent assign", re.compile(r'\.textContent\s*=',           re.I)),
    ("createTextNode",     re.compile(r'\bdocument\.createTextNode\s*\(', re.I)),
    ("innerHTML encode",   re.compile(r'encodeHTML|escapeHtml|htmlEscape', re.I)),
]

# Confidence reduction per sanitizer found
_SANITIZER_CONFIDENCE_PENALTY: float = 0.12

# ---------------------------------------------------------------------------
# Reflection context detection — parser-assisted
# ---------------------------------------------------------------------------

class _TagContextParser(HTMLParser):
    """
    Track whether a given position is inside a <script> tag, an event handler,
    an HTML attribute, or plain HTML body.
    """
    def __init__(self, target_value: str) -> None:
        super().__init__()
        self._target = target_value
        self._in_script = False
        self.contexts: Set[str] = set()

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag == "script":
            self._in_script = True
        for attr_name, attr_val in attrs:
            if attr_val and self._target in attr_val:
                evt = attr_name.lower()
                if evt.startswith("on"):
                    self.contexts.add("event_handler")
                else:
                    self.contexts.add("attribute_value")

    def handle_endtag(self, tag: str) -> None:
        if tag == "script":
            self._in_script = False

    def handle_data(self, data: str) -> None:
        if self._target in data:
            if self._in_script:
                self.contexts.add("script_tag")
            else:
                self.contexts.add("html_body")


def _detect_reflection_context(body: str, value: str) -> List[str]:
    """
    Identify the HTML context in which *value* appears using a two-pass approach:
    1. HTMLParser walk for structural accuracy.
    2. Regex fallback for regex-specific contexts missed by the parser.

    Returns a deduplicated list of context labels.
    """
    contexts: Set[str] = set()

    # Pass 1: HTMLParser-based
    try:
        p = _TagContextParser(value)
        p.feed(body[:32_000])
        contexts.update(p.contexts)
    except Exception:
        pass

    # Pass 2: Regex fallback for edge cases the parser may miss
    start = 0
    while True:
        pos = body.find(value, start)
        if pos == -1:
            break
        start = pos + 1

        snippet_before = body[max(0, pos - 300): pos].lower()

        # Script context
        if re.search(r'<script[^>]*>', snippet_before) and "</script>" not in snippet_before:
            contexts.add("script_tag")

        # Event handler (on* attribute)
        if re.search(rf'(?:{_EVENT_NAMES_JOINED})\s*=\s*["\'][^"\']*$', snippet_before, re.I):
            contexts.add("event_handler")

        # HTML attribute
        if re.search(r'<[a-z][^>]*\s+[a-z-]+=\s*["\'][^"\']*$', snippet_before, re.I):
            contexts.add("attribute_value")

        # JavaScript variable context
        if re.search(r'(?:var|let|const)\s+\w+\s*=\s*["\'][^"\']*$', snippet_before, re.I):
            contexts.add("js_context")

    # Default: if value was found but no specific context matched, flag html_body
    if not contexts and value in body:
        contexts.add("html_body")

    return sorted(contexts)


# ---------------------------------------------------------------------------
# Sink–sanitizer proximity check
# ---------------------------------------------------------------------------

_SANITIZER_PROXIMITY = 500  # characters


def _sanitizer_reaches_sink(body: str, sink_pattern: re.Pattern, sanitizer_pattern: re.Pattern) -> bool:
    """
    Return True if a sanitizer call appears within _SANITIZER_PROXIMITY characters
    of the dangerous sink — a rough but practical indicator that sanitization
    is applied before the sink.
    """
    for sink_m in sink_pattern.finditer(body):
        window_start = max(0, sink_m.start() - _SANITIZER_PROXIMITY)
        window_end   = min(len(body), sink_m.end() + _SANITIZER_PROXIMITY)
        window = body[window_start:window_end]
        if sanitizer_pattern.search(window):
            return True
    return False


def _any_sanitizer_near_sinks(
    body: str,
    sink_patterns: List[Tuple[str, re.Pattern]],
    san_patterns: List[Tuple[str, re.Pattern]],
) -> bool:
    for _, sp in san_patterns:
        for _, sink_p in sink_patterns:
            if _sanitizer_reaches_sink(body, sink_p, sp):
                return True
    return False


# ---------------------------------------------------------------------------
# Source → sink proximity / taint scoring
# ---------------------------------------------------------------------------

def _taint_proximity_score(body: str, sources: List[str], sinks: List[str]) -> float:
    """
    Score 0-1 representing how close (in characters) source and sink patterns
    co-occur. Closer → higher score. Used to boost taint-flow confidence.
    """
    if not sources or not sinks:
        return 0.0

    source_positions: List[int] = []
    for name, pat in _SOURCE_PATTERNS:
        if name in sources:
            for m in pat.finditer(body):
                source_positions.append(m.start())

    sink_positions: List[int] = []
    for name, pat in _CRITICAL_SINKS:
        if name in sinks:
            for m in pat.finditer(body):
                sink_positions.append(m.start())

    if not source_positions or not sink_positions:
        return 0.0

    min_dist = min(
        abs(sp - sk)
        for sp in source_positions
        for sk in sink_positions
    )
    # Score: 1.0 if within 100 chars, decays to 0.3 at 5000 chars
    return round(max(0.30, 1.0 - (min_dist / 5000.0)), 3)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_MIN_PARAM_LEN = 4
_MAX_PARAM_LEN = 120

_INTERESTING_VALUE_RE = re.compile(r'[<>"\'\\/&{}()|=`]')


def _is_interesting_value(value: str) -> bool:
    if len(value) < _MIN_PARAM_LEN or len(value) > _MAX_PARAM_LEN:
        return False
    return bool(_INTERESTING_VALUE_RE.search(value))


def _html_encoded(value: str, body: str) -> bool:
    """Return True if ALL occurrences of value in body are HTML-entity-encoded."""
    if value not in body:
        return False
    encoded_map = {"<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "&": "&amp;"}
    encoded_version = "".join(encoded_map.get(c, c) for c in value)
    raw_count = body.count(value)
    enc_count = body.count(encoded_version)
    # Encoded only if every raw occurrence is also entity-encoded
    return enc_count >= raw_count


def _truncate(text: str, n: int = 120) -> str:
    return text[:n] + "…" if len(text) > n else text


def _finding_key(url: str, check: str, detail: str, context: str = "") -> str:
    return hashlib.sha1(
        f"{url}:{check}:{detail}:{context}".encode()
    ).hexdigest()


def _apply_sanitizer_penalty(confidence: float, sanitizers: List[str]) -> float:
    """Reduce confidence per discovered sanitizer, floored at 0.25."""
    reduced = confidence - len(sanitizers) * _SANITIZER_CONFIDENCE_PENALTY
    return round(max(0.25, reduced), 3)


# ---------------------------------------------------------------------------
# Thread-safe result accumulator
# ---------------------------------------------------------------------------

@dataclass
class XSSFinding:
    url: str
    check: str
    severity: str
    description: str
    evidence: str
    category: str = "xss"
    confidence: float = 0.70
    exploitability: float = 0.60
    framework: str = ""

    def to_dict(self) -> dict:
        return {
            "check": self.check,
            "severity": self.severity,
            "url": self.url,
            "description": self.description,
            "evidence": self.evidence,
            "category": self.category,
            "confidence": round(self.confidence, 2),
            "exploitability": round(self.exploitability, 2),
            "framework": self.framework,
        }


class FindingAccumulator:
    """Async-safe container for XSS findings with deduplication."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._seen: Set[str] = set()
        self.findings: List[XSSFinding] = []

    async def add(self, finding: XSSFinding, dedup_key: str) -> None:
        async with self._lock:
            if dedup_key not in self._seen:
                self._seen.add(dedup_key)
                self.findings.append(finding)


# ---------------------------------------------------------------------------
# CSP parser
# ---------------------------------------------------------------------------

class CSPInfo:
    def __init__(self, csp_value: Optional[str]) -> None:
        self.present = bool(csp_value)
        self.value   = csp_value or ""
        self.weaknesses: List[str] = []
        self._analyse()

    def _analyse(self) -> None:
        if not self.present:
            return
        for label, check_fn in _CSP_WEAKNESS_CHECKS:
            if check_fn(self.value):
                self.weaknesses.append(label)

    @property
    def effective(self) -> bool:
        return self.present and not self.weaknesses

    @classmethod
    def from_body(cls, body: str, extra_headers: Optional[Dict[str, str]] = None) -> "CSPInfo":
        headers = extra_headers or {}
        for k, v in headers.items():
            if k.lower() == _CSP_HEADER_MARKER:
                return cls(v)
        m = _CSP_META_RE.search(body)
        if m:
            return cls(m.group(1))
        return cls(None)


# ---------------------------------------------------------------------------
# HTML page analyser
# ---------------------------------------------------------------------------

async def _analyse_html(
    page_url: str,
    body: str,
    accumulator: FindingAccumulator,
    response_headers: Optional[Dict[str, str]] = None,
) -> None:
    """Full passive analysis of one HTML page body."""

    csp = CSPInfo.from_body(body, response_headers)

    # ── 1. Sanitizer inventory ───────────────────────────────────────────────
    sanitizers_present: List[str] = []
    for san_name, pattern in _SANITIZERS:
        if pattern.search(body):
            sanitizers_present.append(san_name)

    # ── 2. Critical sink detection ───────────────────────────────────────────
    sinks_found: List[str] = []
    for sink_name, pattern in _CRITICAL_SINKS:
        if pattern.search(body):
            sinks_found.append(sink_name)
            key = _finding_key(page_url, "dangerous_sink", sink_name)

            # Check whether a sanitizer is provably applied near this sink
            sanitizer_near = _any_sanitizer_near_sinks(
                body, [(sink_name, pattern)], _SANITIZERS
            )
            base_conf = 0.85
            base_exploit = 0.80
            if sanitizer_near:
                base_conf    = _apply_sanitizer_penalty(base_conf, ["near"])
                base_exploit = max(0.30, base_exploit - 0.25)

            await accumulator.add(XSSFinding(
                url=page_url,
                check="XSS Risk — Dangerous Sink",
                severity="High",
                description=(
                    f"Dangerous DOM sink '{sink_name}' present. "
                    "If attacker-controlled data reaches this sink without sanitization, "
                    "script injection is exploitable."
                    + (" Sanitizer detected nearby — verify reach." if sanitizer_near else "")
                ),
                evidence=f"sink={sink_name}" + (" sanitizer_nearby=yes" if sanitizer_near else ""),
                confidence=base_conf,
                exploitability=base_exploit,
            ), key)

    for sink_name, pattern in _HIGH_SINKS:
        if pattern.search(body):
            sinks_found.append(sink_name)
            key = _finding_key(page_url, "sink_high", sink_name)
            await accumulator.add(XSSFinding(
                url=page_url,
                check="XSS Risk — Potentially Dangerous Sink",
                severity="High",
                description=(
                    f"Potentially dangerous DOM sink '{sink_name}' present. "
                    "Requires taint analysis to confirm exploitability."
                ),
                evidence=f"sink={sink_name}",
                confidence=0.72,
                exploitability=0.65,
            ), key)

    # ── 3. Framework-specific unsafe patterns ────────────────────────────────
    for framework, pattern_name, pattern in _FRAMEWORK_SINKS:
        if pattern.search(body):
            key = _finding_key(page_url, "framework_sink", f"{framework}:{pattern_name}")
            conf = 0.90
            if sanitizers_present:
                conf = _apply_sanitizer_penalty(conf, sanitizers_present)
            await accumulator.add(XSSFinding(
                url=page_url,
                check="XSS Risk — Framework Unsafe Pattern",
                severity="High",
                description=(
                    f"[{framework}] Unsafe pattern '{pattern_name}' detected. "
                    "This bypasses the framework's built-in XSS protection and requires "
                    "rigorous sanitization of all upstream data."
                    + (f" Sanitizers present: {', '.join(sanitizers_present)}."
                       if sanitizers_present else "")
                ),
                evidence=f"framework={framework} pattern={pattern_name}",
                confidence=conf,
                exploitability=0.84,
                framework=framework,
            ), key)

    # ── 4. Source → sink taint flow ───────────────────────────────────────────
    sources_found: List[str] = [n for n, p in _SOURCE_PATTERNS if p.search(body)]

    if sources_found and sinks_found:
        proximity = _taint_proximity_score(body, sources_found, sinks_found)
        base_conf = 0.78 + proximity * 0.15
        if sanitizers_present:
            base_conf = _apply_sanitizer_penalty(base_conf, sanitizers_present)
        key = _finding_key(page_url, "taint_flow", f"{','.join(sinks_found[:3])}")
        await accumulator.add(XSSFinding(
            url=page_url,
            check="XSS Risk — Source-to-Sink Taint Flow",
            severity="Critical",
            description=(
                "Tainted user-controlled source co-located with dangerous DOM sink. "
                "High probability of exploitable DOM-based XSS. "
                f"Proximity score: {proximity:.2f} (1.0 = very close)."
                + (f" Sanitizers detected: {', '.join(sanitizers_present)} — "
                   "verify they intercept all paths to each sink."
                   if sanitizers_present else "")
            ),
            evidence=(
                f"sources={','.join(sources_found[:3])} → sinks={','.join(sinks_found[:3])} "
                f"proximity={proximity:.2f}"
            ),
            confidence=round(min(0.95, base_conf), 3),
            exploitability=round(min(0.92, 0.80 + proximity * 0.12), 3),
        ), key)

    # ── 5. Reflection detection ───────────────────────────────────────────────
    parsed   = urlparse(page_url)
    params   = parse_qs(parsed.query, keep_blank_values=False)

    for param_name, values in params.items():
        for raw_value in values:
            value = unescape(raw_value)
            if not _is_interesting_value(value):
                continue
            if value not in body:
                continue
            if _html_encoded(value, body):
                continue

            contexts = _detect_reflection_context(body, value)
            if not contexts:
                continue

            for ctx_label in contexts:
                sev = "High" if ctx_label in ("script_tag", "event_handler") else "Medium"
                conf = 0.80 if sev == "High" else 0.68
                exploit = 0.74 if sev == "High" else 0.56

                # Modulate by sanitizer — reduce but never suppress
                if sanitizers_present:
                    conf    = _apply_sanitizer_penalty(conf, sanitizers_present)
                    exploit = max(0.25, exploit - 0.15 * len(sanitizers_present))

                key = _finding_key(page_url, "reflection", param_name, ctx_label)
                await accumulator.add(XSSFinding(
                    url=page_url,
                    check="XSS Risk — Reflected Parameter",
                    severity=sev,
                    description=(
                        f"URL parameter '{param_name}' reflected unencoded in the response "
                        f"within a '{ctx_label}' context. May be exploitable via reflected XSS."
                        + (f" Sanitizers present: {', '.join(sanitizers_present)} — "
                           "verify they cover this reflection point."
                           if sanitizers_present else "")
                    ),
                    evidence=(
                        f"param={param_name} context={ctx_label} "
                        f"value={_truncate(value, 40)}"
                        + (f" sanitizers={','.join(sanitizers_present)}"
                           if sanitizers_present else "")
                    ),
                    confidence=conf,
                    exploitability=exploit,
                ), key)

    # ── 6. Inline event handlers ──────────────────────────────────────────────
    seen_events: Set[str] = set()
    for match in _INLINE_EVENT_RE.finditer(body):
        event_name  = match.group(1).lower()
        handler_val = match.group(2) or match.group(3) or ""
        if not handler_val or len(handler_val) < 5:
            continue
        if event_name in seen_events:
            continue
        seen_events.add(event_name)
        key = _finding_key(page_url, "inline_event", event_name)
        await accumulator.add(XSSFinding(
            url=page_url,
            check="XSS Risk — Inline Event Handler",
            severity="Low",
            description=(
                f"Inline event handler '{event_name}' with non-trivial body found. "
                "Inline handlers bypass 'unsafe-inline' CSP protections and may execute "
                "attacker-controlled data if the handler is not sanitized."
            ),
            evidence=f"event={event_name} handler={_truncate(handler_val, 60)}",
            confidence=0.55,
            exploitability=0.40,
        ), key)

    # ── 7. Stored XSS surface indicators ─────────────────────────────────────
    persistent_flow = any(p.search(body) for p in _STORED_FLOW_INDICATORS)
    for surface_name, pattern in _STORED_SURFACE_PATTERNS:
        if pattern.search(body):
            key = _finding_key(page_url, "stored_surface", surface_name)
            conf    = 0.60 if persistent_flow else 0.40
            exploit = 0.62 if persistent_flow else 0.45
            await accumulator.add(XSSFinding(
                url=page_url,
                check="XSS Risk — Stored XSS Surface",
                severity="Medium",
                description=(
                    f"Persistent input surface '{surface_name}' detected"
                    + (" with backend persistence flow indicators" if persistent_flow else "")
                    + ". If user-supplied content is stored and rendered without sanitization, "
                    "stored XSS is possible."
                ),
                evidence=f"surface={surface_name} persistent_flow={persistent_flow}",
                confidence=conf,
                exploitability=exploit,
            ), key)

    # ── 8. Template injection indicators ─────────────────────────────────────
    for template_name, pattern, benign_guard in _TEMPLATE_PATTERNS:
        for m in pattern.finditer(body):
            match_text = m.group(0)
            # Skip if inside a comment
            pre = body[max(0, m.start() - 80): m.start()]
            if re.search(r'(?:/\*|//|#|<!--)', pre):
                continue
            # Skip if surrounded by benign Angular/Vue framework markers
            if benign_guard and benign_guard.search(body[max(0, m.start()-200): m.end()+200]):
                continue
            # Skip pure static strings (no variable-like content)
            inner = match_text.strip("{%<>=- ").strip()
            if not re.search(r'[a-zA-Z_$]', inner):
                continue
            key = _finding_key(page_url, "template_injection", template_name + match_text[:20])
            await accumulator.add(XSSFinding(
                url=page_url,
                check="XSS Risk — Template Injection Pattern",
                severity="Medium",
                description=(
                    f"Template expression pattern '{template_name}' detected in response. "
                    "If user input influences the template context, client-side or "
                    "server-side template injection may be possible."
                ),
                evidence=f"pattern={template_name} match={_truncate(match_text, 60)}",
                confidence=0.55,
                exploitability=0.50,
            ), key)
            break  # One finding per pattern per page

    # ── 9. CSP bypass patterns ────────────────────────────────────────────────
    for bypass_name, pattern in _CSP_BYPASS_PATTERNS:
        if pattern.search(body):
            key = _finding_key(page_url, "csp_bypass", bypass_name)
            await accumulator.add(XSSFinding(
                url=page_url,
                check="XSS Risk — CSP Bypass Pattern",
                severity="Medium",
                description=(
                    f"CSP bypass pattern '{bypass_name}' detected. "
                    "This may allow XSS exploitation even when a Content-Security-Policy is present."
                ),
                evidence=f"bypass={bypass_name}",
                confidence=0.68,
                exploitability=0.72,
            ), key)

    # ── 10. CSP evaluation ─────────────────────────────────────────────────────
    if not csp.present:
        key = _finding_key(page_url, "missing_csp", "")
        await accumulator.add(XSSFinding(
            url=page_url,
            check="XSS Risk — Missing Content-Security-Policy",
            severity="Low",
            description=(
                "No Content-Security-Policy header or meta tag found. "
                "A CSP is a critical defence-in-depth control that limits XSS exploitability."
            ),
            evidence="missing=Content-Security-Policy",
            confidence=0.99,
            exploitability=0.30,
        ), key)
    elif csp.weaknesses:
        key = _finding_key(page_url, "weak_csp", ",".join(csp.weaknesses[:3]))
        await accumulator.add(XSSFinding(
            url=page_url,
            check="XSS Risk — Weak Content-Security-Policy",
            severity="Low",
            description=(
                f"Content-Security-Policy present but contains weaknesses: "
                f"{', '.join(csp.weaknesses)}. These may be exploitable for CSP bypass."
            ),
            evidence=f"csp_weaknesses={','.join(csp.weaknesses)} | policy={_truncate(csp.value, 80)}",
            confidence=0.90,
            exploitability=0.48,
        ), key)


# ---------------------------------------------------------------------------
# JavaScript file analyser
# ---------------------------------------------------------------------------

async def _analyse_js(
    page_url: str,
    body: str,
    accumulator: FindingAccumulator,
) -> None:
    """Focused analysis for standalone JavaScript files."""

    # Sanitizer inventory
    sanitizers_present: List[str] = [n for n, p in _SANITIZERS if p.search(body)]

    # Sinks
    sinks_found: List[str] = []
    for sink_name, pattern in _CRITICAL_SINKS:
        if pattern.search(body):
            sinks_found.append(sink_name)
            sanitizer_near = _any_sanitizer_near_sinks(
                body, [(sink_name, pattern)], _SANITIZERS
            )
            base_conf    = 0.82
            base_exploit = 0.72
            if sanitizer_near:
                base_conf    = _apply_sanitizer_penalty(base_conf, ["near"])
                base_exploit = max(0.28, base_exploit - 0.22)
            key = _finding_key(page_url, "js_sink", sink_name)
            await accumulator.add(XSSFinding(
                url=page_url,
                check="XSS Risk — JS File Dangerous Sink",
                severity="High",
                description=(
                    f"Dangerous sink '{sink_name}' in JavaScript resource. "
                    "Determine whether the upstream data is user-controlled."
                    + (" Sanitizer detected nearby." if sanitizer_near else "")
                ),
                evidence=f"sink={sink_name}",
                confidence=base_conf,
                exploitability=base_exploit,
            ), key)

    # Sources
    sources_found: List[str] = [n for n, p in _SOURCE_PATTERNS if p.search(body)]

    # Source → sink taint in JS
    if sources_found and sinks_found:
        proximity = _taint_proximity_score(body, sources_found, sinks_found)
        base_conf = 0.75 + proximity * 0.15
        if sanitizers_present:
            base_conf = _apply_sanitizer_penalty(base_conf, sanitizers_present)
        key = _finding_key(page_url, "js_taint_flow", ",".join(sinks_found[:2]))
        await accumulator.add(XSSFinding(
            url=page_url,
            check="XSS Risk — JS Source-to-Sink Taint Flow",
            severity="Critical",
            description=(
                "User-controlled source and dangerous sink co-located in a JavaScript file. "
                "Strong indicator of DOM-based XSS. Perform taint analysis to confirm."
                + (f" Sanitizers detected: {', '.join(sanitizers_present)} — verify coverage."
                   if sanitizers_present else "")
            ),
            evidence=(
                f"sources={','.join(sources_found[:3])} → sinks={','.join(sinks_found[:3])} "
                f"proximity={proximity:.2f}"
            ),
            confidence=round(min(0.93, base_conf), 3),
            exploitability=round(min(0.90, 0.80 + proximity * 0.10), 3),
        ), key)

    # Framework sinks in JS
    for framework, pattern_name, pattern in _FRAMEWORK_SINKS:
        if pattern.search(body):
            conf = 0.86
            if sanitizers_present:
                conf = _apply_sanitizer_penalty(conf, sanitizers_present)
            key = _finding_key(page_url, "js_framework_sink", f"{framework}:{pattern_name}")
            await accumulator.add(XSSFinding(
                url=page_url,
                check="XSS Risk — JS Framework Unsafe Pattern",
                severity="High",
                description=(
                    f"[{framework}] Unsafe pattern '{pattern_name}' in JavaScript file. "
                    "Ensure upstream data is fully sanitized."
                ),
                evidence=f"framework={framework} pattern={pattern_name}",
                confidence=conf,
                exploitability=0.80,
                framework=framework,
            ), key)


# ---------------------------------------------------------------------------
# Page-type dispatcher
# ---------------------------------------------------------------------------

def _is_js_file(url: str) -> bool:
    path = urlparse(url).path.lower()
    return path.endswith((".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"))


async def _analyse_page(
    page_url: str,
    body: str,
    accumulator: FindingAccumulator,
    response_headers: Optional[Dict[str, str]] = None,
) -> None:
    if not body or len(body.strip()) < 20:
        return
    if _is_js_file(page_url):
        await _analyse_js(page_url, body, accumulator)
    else:
        await _analyse_html(page_url, body, accumulator, response_headers)


# ---------------------------------------------------------------------------
# Severity weight for sorting
# ---------------------------------------------------------------------------

_SEV_WEIGHT: Dict[str, int] = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


# ---------------------------------------------------------------------------
# Public async interface — FORTIS-compatible
# ---------------------------------------------------------------------------

async def scan(
    url: str,
    crawl_depth: int = 2,
    insecure: bool = False,
    pre_crawled: Optional[Dict[str, Optional[str]]] = None,
    response_headers_map: Optional[Dict[str, Dict[str, str]]] = None,
) -> dict:
    """
    Passive XSS analysis of pre-crawled content.

    Parameters
    ----------
    url                  : Scan target (ScanResult identity only — no requests made).
    crawl_depth          : Ignored — crawler already ran; retained for interface parity.
    insecure             : Ignored — no requests made.
    pre_crawled          : {page_url: html_or_js_body | None}
    response_headers_map : {page_url: {header_name: header_value}} — for CSP header detection.

    Returns
    -------
    dict — FORTIS ScanResult-compatible output.
    """
    result: Dict[str, Any] = {
        "target": url,
        "scanner": "xss_scanner",
        "findings": [],
        "scanned_urls": [],
        "errors": [],
        "meta": {},
    }

    if not pre_crawled:
        result["errors"].append("xss_scanner: no pre-crawled content available")
        return result

    result["scanned_urls"] = list(pre_crawled.keys())
    headers_map = response_headers_map or {}
    accumulator = FindingAccumulator()

    # Correct async pattern: create coroutines and gather them directly.
    # NEVER use asyncio.run() inside an executor — it creates a nested event loop.
    tasks = []
    for page_url, body in pre_crawled.items():
        if not body:
            continue
        page_headers = headers_map.get(page_url)
        tasks.append(_analyse_page(page_url, body, accumulator, page_headers))

    gather_results = await asyncio.gather(*tasks, return_exceptions=True)

    for exc in gather_results:
        if isinstance(exc, Exception):
            logger.warning("Analysis error: %s", exc)
            result["errors"].append(str(exc))

    findings_dicts = [f.to_dict() for f in accumulator.findings]
    findings_dicts.sort(key=lambda f: _SEV_WEIGHT.get(f.get("severity", "Low"), 4))

    result["findings"] = findings_dicts

    severity_counts: Dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings_dicts:
        sev = f.get("severity", "Low")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    result["meta"]["total_findings"]    = len(findings_dicts)
    result["meta"]["scanned_url_count"] = len(result["scanned_urls"])
    result["meta"]["severity_counts"]   = severity_counts

    return result
