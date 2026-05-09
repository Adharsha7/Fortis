
from __future__ import annotations

import asyncio
import re
import ssl
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

import aiohttp

# ---------------------------------------------------------------------------
# Shared Constants
# ---------------------------------------------------------------------------

DEFAULT_TIMEOUT: int = 12
DEFAULT_MAX_CONCURRENT: int = 20
DEFAULT_CRAWL_DEPTH: int = 3
MAX_CRAWL_DEPTH: int = 5
MAX_BODY_BYTES: int = 1_048_576       # 1 MB
FETCH_RETRIES: int = 3
RETRY_BACKOFF: float = 0.5
USER_AGENT: str = "Mozilla/5.0 (compatible; SecurityScanner/3.0)"

SEVERITY_ORDER: dict[str, int] = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

# ---------------------------------------------------------------------------
# Common Dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Finding:
    check: str
    severity: str
    description: str
    source_url: str
    evidence: str = ""
    category: str = "general"
    masked_value: str = ""

    def as_dict(self) -> dict:
        d: dict = {
            "check": self.check,
            "severity": self.severity,
            "description": self.description,
            "source_url": self.source_url,
            "evidence": self.evidence,
        }
        if self.category and self.category != "general":
            d["category"] = self.category
        if self.masked_value:
            d["masked_value"] = self.masked_value
        return d


@dataclass
class ScanResult:
    target: str
    scanned_urls: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    _seen_keys: set[tuple] = field(default_factory=set, repr=False, compare=False)

    def add(
        self,
        check: str,
        severity: str,
        description: str,
        source_url: str,
        evidence: str = "",
        category: str = "general",
        masked_value: str = "",
    ) -> None:
        key = (check, evidence[:80], source_url, masked_value[:20])
        if key not in self._seen_keys:
            self._seen_keys.add(key)
            self.findings.append(
                Finding(
                    check=check,
                    severity=severity,
                    description=description,
                    source_url=source_url,
                    evidence=evidence,
                    category=category,
                    masked_value=masked_value,
                )
            )

    def add_finding(self, finding: Finding) -> None:
        key = (finding.check, finding.evidence[:80], finding.source_url, finding.masked_value[:20])
        if key not in self._seen_keys:
            self._seen_keys.add(key)
            self.findings.append(finding)

    def to_dict(self) -> dict:
        sorted_findings = sorted(
            self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99)
        )
        return {
            "target": self.target,
            "scanned_urls": sorted(set(self.scanned_urls)),
            "findings": [f.as_dict() for f in sorted_findings],
            "errors": self.errors,
        }

# ---------------------------------------------------------------------------
# SSL / Session Factories
# ---------------------------------------------------------------------------

def make_ssl_context(insecure: bool = False) -> ssl.SSLContext:
    """Return an SSL context. If insecure=True, certificate verification is disabled."""
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def make_connector(insecure: bool = False) -> aiohttp.TCPConnector:
    return aiohttp.TCPConnector(ssl=make_ssl_context(insecure))


def make_timeout(seconds: int = DEFAULT_TIMEOUT) -> aiohttp.ClientTimeout:
    return aiohttp.ClientTimeout(total=seconds, connect=5)


def make_session(
    insecure: bool = False,
    timeout: int = DEFAULT_TIMEOUT,
    user_agent: str = USER_AGENT,
) -> aiohttp.ClientSession:
    """Create a configured aiohttp session. Caller is responsible for closing it."""
    return aiohttp.ClientSession(
        connector=make_connector(insecure=insecure),
        timeout=make_timeout(timeout),
        headers={"User-Agent": user_agent},
    )

# ---------------------------------------------------------------------------
# Async Fetch with Retries
# ---------------------------------------------------------------------------

async def fetch(
    session: aiohttp.ClientSession,
    url: str,
    semaphore: asyncio.Semaphore,
    *,
    allow_redirects: bool = True,
    max_bytes: int = MAX_BODY_BYTES,
    accept_statuses: Optional[set[int]] = None,
) -> tuple[Optional[aiohttp.ClientResponse], Optional[str], Optional[str]]:
    """
    Fetch *url* with retry and exponential backoff.

    Returns (response, body_text, error_string).
    On success: (response, body, None)
    On failure: (None, None, error_message)

    Args:
        accept_statuses: If provided, only these HTTP statuses are treated as valid body responses.
                         Other statuses return (resp, None, "HTTP N").
    """
    last_error: str = "Unknown error"
    async with semaphore:
        for attempt in range(FETCH_RETRIES):
            try:
                async with session.get(url, allow_redirects=allow_redirects) as resp:
                    if accept_statuses is not None and resp.status not in accept_statuses:
                        return resp, None, f"HTTP {resp.status}"
                    chunks: list[bytes] = []
                    total = 0
                    async for chunk in resp.content.iter_chunked(8192):
                        chunks.append(chunk)
                        total += len(chunk)
                        if total >= max_bytes:
                            break
                    raw = b"".join(chunks)
                    try:
                        body = raw.decode("utf-8", errors="replace")
                    except Exception:
                        body = ""
                    return resp, body, None
            except asyncio.TimeoutError:
                last_error = "Request timed out"
            except aiohttp.ClientConnectorError as exc:
                last_error = f"Connection error: {exc}"
                break   # No point retrying connection-refused
            except aiohttp.TooManyRedirects:
                last_error = "Too many redirects"
                break
            except aiohttp.ClientError as exc:
                last_error = str(exc)
            if attempt < FETCH_RETRIES - 1:
                await asyncio.sleep(RETRY_BACKOFF * (2 ** attempt))
    return None, None, last_error

# ---------------------------------------------------------------------------
# URL Utilities
# ---------------------------------------------------------------------------

_HREF_RE = re.compile(r'href=["\']([^"\'#\s]{3,})["\']', re.IGNORECASE)
_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
_LINK_HREF_RE = re.compile(r'<link[^>]+href=["\']([^"\']+)["\']', re.IGNORECASE)
_JS_URL_RE = re.compile(
    r'(?:fetch|axios\.(?:get|post|put|delete|patch)|XMLHttpRequest|http\.(?:get|post))'
    r'\s*\(\s*["\']([^"\']{5,200})["\']',
    re.IGNORECASE,
)
_JS_IMPORT_RE = re.compile(r'(?:import|require)\s*\(?["\']([^"\']+)["\']', re.IGNORECASE)


def normalize_url(base: str, href: str) -> Optional[str]:
    """Resolve *href* against *base*, returning None for non-HTTP(S) or invalid URLs."""
    href = href.strip()
    if not href or href.startswith(("javascript:", "mailto:", "tel:", "data:")):
        return None
    try:
        joined = urljoin(base, href)
        parsed = urlparse(joined)
        if parsed.scheme not in ("http", "https"):
            return None
        # Strip fragment
        return parsed._replace(fragment="").geturl()
    except Exception:
        return None


def is_same_origin(url: str, base_netloc: str, *, allow_subdomains: bool = False) -> bool:
    """Return True if *url* belongs to *base_netloc* (or its subdomains if allowed)."""
    netloc = urlparse(url).netloc
    if netloc == base_netloc:
        return True
    if allow_subdomains:
        base_domain = base_netloc.split(":", 1)[0]
        host = netloc.split(":", 1)[0]
        return host == base_domain or host.endswith("." + base_domain)
    return False


def is_js_url(url: str) -> bool:
    path = urlparse(url).path.lower()
    return path.endswith(".js") or ".js?" in path


def extract_links(
    html: str,
    base_url: str,
    *,
    include_js_imports: bool = True,
    include_api_calls: bool = True,
) -> list[str]:
    """
    Extract all discovered links from HTML/JS content.
    Returns a deduplicated list of absolute URLs (not normalized to origin).
    """
    links: list[str] = []
    for pattern in (_HREF_RE, _SCRIPT_SRC_RE, _LINK_HREF_RE):
        for href in pattern.findall(html):
            norm = normalize_url(base_url, href)
            if norm:
                links.append(norm)
    if include_api_calls:
        for href in _JS_URL_RE.findall(html):
            norm = normalize_url(base_url, href)
            if norm:
                links.append(norm)
    if include_js_imports:
        for href in _JS_IMPORT_RE.findall(html):
            norm = normalize_url(base_url, href)
            if norm:
                links.append(norm)
    return list(dict.fromkeys(links))  # preserve order, deduplicate

# ---------------------------------------------------------------------------
# BFS Async Crawler
# ---------------------------------------------------------------------------

async def crawl(
    session: aiohttp.ClientSession,
    start_url: str,
    semaphore: asyncio.Semaphore,
    *,
    depth: int = DEFAULT_CRAWL_DEPTH,
    allow_subdomains: bool = False,
    prioritize_js: bool = True,
) -> dict[str, Optional[str]]:
    """
    Breadth-first async crawler starting from *start_url*.

    Args:
        depth:            Max crawl depth (capped at MAX_CRAWL_DEPTH).
        allow_subdomains: If True, also follow links to subdomains of the base host.
        prioritize_js:    If True, JS files are fetched before HTML pages in each batch.

    Returns:
        A dict mapping {url -> body_text | None}.
        body_text is None when the fetch failed or the page returned no usable body.
    """
    depth = min(depth, MAX_CRAWL_DEPTH)
    base_netloc = urlparse(start_url).netloc
    visited: dict[str, Optional[str]] = {}
    queue: list[tuple[str, int]] = [(start_url, 0)]

    while queue:
        # Optionally prioritize JS files within each BFS wave
        if prioritize_js:
            js_batch = [(u, d) for u, d in queue if is_js_url(u)]
            other_batch = [(u, d) for u, d in queue if not is_js_url(u)]
            current_batch = js_batch + other_batch
        else:
            current_batch = list(queue)
        queue = []

        to_fetch = [(u, d) for u, d in current_batch if u not in visited]
        if not to_fetch:
            break

        # Mark as visited before fetching to prevent duplicate enqueues
        for u, _ in to_fetch:
            visited[u] = None

        results = await asyncio.gather(
            *[fetch(session, u, semaphore) for u, _ in to_fetch],
            return_exceptions=True,
        )

        for (url, d), result in zip(to_fetch, results):
            if isinstance(result, Exception):
                continue
            resp, body, error = result
            if error or body is None:
                continue
            visited[url] = body

            if d < depth:
                for link in extract_links(body, url):
                    if link not in visited and is_same_origin(
                        link, base_netloc, allow_subdomains=allow_subdomains
                    ):
                        queue.append((link, d + 1))

    return visited
