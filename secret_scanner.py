
from __future__ import annotations

import asyncio
import json
import math
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Optional

from core_utils import (
    DEFAULT_CRAWL_DEPTH,
    DEFAULT_MAX_CONCURRENT,
    DEFAULT_TIMEOUT,
    MAX_CRAWL_DEPTH,
    SEVERITY_ORDER,
    ScanResult,
    crawl,
    make_session,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MIN_ENTROPY: float = 3.5
MIN_KEY_LENGTH: int = 16
MASK_VISIBLE_CHARS: int = 6

DUMMY_VALUES: frozenset[str] = frozenset({
    "your_api_key", "your-api-key", "api_key_here", "replace_me",
    "xxxxxxxxxxxx", "xxxxxxxxxxxxxxxx", "000000000000", "changeme",
    "placeholder", "example", "test", "dummy", "sample",
    "insert_key_here", "sk-xxxx", "sk-test", "your_token_here",
    "enter_key", "your_openai_key", "your_anthropic_key",
    "aaaaaaaaaaaaaaaa", "1234567890123456", "abcdefghijklmnop",
    "none", "null", "undefined", "false", "true",
})

# ---------------------------------------------------------------------------
# Detection Patterns
# ---------------------------------------------------------------------------

PATTERNS: dict[str, dict] = {
    # ── Cloud Providers ──────────────────────────────────────────────────────
    "AWS Access Key": {
        "regex": r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])",
        "min_length": 20,
        "entropy_check": True,
        "severity": "Critical",
        "category": "cloud",
    },
    "AWS Secret Key": {
        "regex": r"(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key\s*[=:\"'\s]+([A-Za-z0-9/+=]{40})",
        "min_length": 40,
        "entropy_check": True,
        "severity": "Critical",
        "category": "cloud",
    },
    "Google API Key": {
        "regex": r"(AIza[0-9A-Za-z\-_]{35})",
        "min_length": 39,
        "entropy_check": False,
        "severity": "High",
        "category": "cloud",
    },
    "Firebase URL": {
        "regex": r"(https://[a-zA-Z0-9\-]+\.firebaseio\.com)",
        "min_length": 30,
        "entropy_check": False,
        "severity": "Medium",
        "category": "cloud",
    },
    "GCP Service Account": {
        "regex": r'"type"\s*:\s*"service_account"',
        "min_length": 0,
        "entropy_check": False,
        "severity": "Critical",
        "category": "cloud",
    },

    # ── Source Control ───────────────────────────────────────────────────────
    "GitHub Personal Access Token": {
        "regex": r"\b(ghp_[a-zA-Z0-9]{36})\b",
        "min_length": 40,
        "entropy_check": True,
        "severity": "High",
        "category": "vcs",
    },
    "GitHub OAuth Token": {
        "regex": r"\b(gho_[a-zA-Z0-9]{36})\b",
        "min_length": 40,
        "entropy_check": True,
        "severity": "High",
        "category": "vcs",
    },
    "GitHub App Token": {
        "regex": r"\b(ghs_[a-zA-Z0-9]{36})\b",
        "min_length": 40,
        "entropy_check": True,
        "severity": "High",
        "category": "vcs",
    },
    "GitHub Fine-Grained PAT": {
        "regex": r"\b(github_pat_[a-zA-Z0-9_]{82})\b",
        "min_length": 93,
        "entropy_check": True,
        "severity": "High",
        "category": "vcs",
    },

    # ── Communication / SaaS ─────────────────────────────────────────────────
    "Slack Bot Token": {
        "regex": r"(xoxb-[0-9]{9,13}-[0-9]{9,13}-[a-zA-Z0-9]{24})",
        "min_length": 50,
        "entropy_check": False,
        "severity": "High",
        "category": "saas",
    },
    "Slack User Token": {
        "regex": r"(xoxp-[0-9]{9,13}-[0-9]{9,13}-[0-9]{9,13}-[a-zA-Z0-9]{32})",
        "min_length": 60,
        "entropy_check": False,
        "severity": "High",
        "category": "saas",
    },
    "Slack Webhook": {
        "regex": r"(https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24,})",
        "min_length": 60,
        "entropy_check": False,
        "severity": "High",
        "category": "saas",
    },

    # ── Payments ─────────────────────────────────────────────────────────────
    "Stripe Live Secret Key": {
        "regex": r"\b(sk_live_[a-zA-Z0-9]{24,})\b",
        "min_length": 32,
        "entropy_check": True,
        "severity": "Critical",
        "category": "payment",
    },
    "Stripe Publishable Key": {
        "regex": r"\b(pk_live_[a-zA-Z0-9]{24,})\b",
        "min_length": 32,
        "entropy_check": False,
        "severity": "Medium",
        "category": "payment",
    },
    "Stripe Test Secret Key": {
        "regex": r"\b(sk_test_[a-zA-Z0-9]{24,})\b",
        "min_length": 32,
        "entropy_check": True,
        "severity": "Low",
        "category": "payment",
    },

    # ── AI Services ──────────────────────────────────────────────────────────
    "OpenAI API Key": {
        "regex": r"\b(sk-[a-zA-Z0-9]{20,})\b",
        "min_length": 24,
        "entropy_check": True,
        "severity": "High",
        "category": "ai",
    },
    "Anthropic API Key": {
        "regex": r"\b(sk-ant-[a-zA-Z0-9\-_]{40,})\b",
        "min_length": 50,
        "entropy_check": True,
        "severity": "High",
        "category": "ai",
    },
    "HuggingFace Token": {
        "regex": r"\b(hf_[a-zA-Z0-9]{32,})\b",
        "min_length": 35,
        "entropy_check": True,
        "severity": "High",
        "category": "ai",
    },
    "Cohere API Key": {
        "regex": r"(?i)cohere[_\-\s]?(?:api[_\-\s]?)?key\s*[=:\"'\s]+([A-Za-z0-9\-_]{32,})",
        "min_length": 32,
        "entropy_check": True,
        "severity": "High",
        "category": "ai",
    },
    "Replicate API Token": {
        "regex": r"\b(r8_[a-zA-Z0-9]{37})\b",
        "min_length": 40,
        "entropy_check": True,
        "severity": "High",
        "category": "ai",
    },

    # ── AI Endpoint / Misconfiguration ───────────────────────────────────────
    "Exposed OpenAI Endpoint": {
        "regex": r"(https://api\.openai\.com/v\d+/[a-z/]+)",
        "min_length": 25,
        "entropy_check": False,
        "severity": "Medium",
        "category": "ai_config",
    },
    "Exposed Anthropic Endpoint": {
        "regex": r"(https://api\.anthropic\.com/v\d+/[a-z/]+)",
        "min_length": 25,
        "entropy_check": False,
        "severity": "Medium",
        "category": "ai_config",
    },
    "Hardcoded AI Model ID": {
        "regex": r'(?i)\bmodel\b[_\-\s]*[=:"\']\s*(gpt-4[^"\s,;\']{0,30}|gpt-3\.5[^"\s,;\']{0,30}|claude-[23][^"\s,;\']{0,30}|gemini-[^"\s,;\']{0,30})',
        "min_length": 5,
        "entropy_check": False,
        "severity": "Low",
        "category": "ai_config",
    },
    "Exposed System Prompt": {
        "regex": r'(?i)system[_\-\s]*prompt\s*[=:"\']\s*([^\n"\']{30,})',
        "min_length": 30,
        "entropy_check": False,
        "severity": "Medium",
        "category": "ai_config",
    },
    "AI Debug Mode Enabled": {
        "regex": r'(?i)(?:debug|verbose)[_\-\s]*[=:"\']\s*(?:true|1|yes)',
        "min_length": 0,
        "entropy_check": False,
        "severity": "Low",
        "category": "ai_config",
    },

    # ── Cryptographic Material ───────────────────────────────────────────────
    "RSA / PEM Private Key": {
        "regex": r"(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)",
        "min_length": 0,
        "entropy_check": False,
        "severity": "Critical",
        "category": "crypto",
    },
    "JWT Token": {
        "regex": r"\b(eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]*)\b",
        "min_length": 30,
        "entropy_check": False,
        "severity": "Medium",
        "category": "crypto",
    },

    # ── Generic ──────────────────────────────────────────────────────────────
    "Generic API Key": {
        "regex": r'(?i)(?:api[_\-]?key|apikey)\s*[=:"\']\s*([A-Za-z0-9_\-]{20,60})',
        "min_length": 20,
        "entropy_check": True,
        "severity": "Medium",
        "category": "generic",
    },
    "Generic Password": {
        "regex": r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,50})["\']',
        "min_length": 8,
        "entropy_check": True,
        "severity": "Medium",
        "category": "generic",
    },
    "Generic Secret": {
        "regex": r'(?i)(?:secret|token)\s*[=:]\s*["\']([A-Za-z0-9_\-\.]{16,80})["\']',
        "min_length": 16,
        "entropy_check": True,
        "severity": "Medium",
        "category": "generic",
    },
}

# Compile all patterns once at import time
_COMPILED_PATTERNS: dict[str, re.Pattern] = {}
for _name, _cfg in PATTERNS.items():
    try:
        _COMPILED_PATTERNS[_name] = re.compile(_cfg["regex"], re.IGNORECASE)
    except re.error:
        pass

# ---------------------------------------------------------------------------
# Secret-specific Finding dataclass (extends the common shape)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SecretFinding:
    service: str
    masked_value: str
    source_url: str
    severity: str
    category: str
    description: str

    def as_dict(self) -> dict:
        return {
            "check": self.service,
            "severity": self.severity,
            "category": self.category,
            "masked_value": self.masked_value,
            "description": self.description,
            "source_url": self.source_url,
        }


@dataclass
class SecretScanResult:
    target: str
    scanned_urls: list[str] = field(default_factory=list)
    findings: list[SecretFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        sorted_findings = sorted(
            self.findings,
            key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.category),
        )
        return {
            "target": self.target,
            "scanned_urls": sorted(set(self.scanned_urls)),
            "findings": [f.as_dict() for f in sorted_findings],
            "errors": self.errors,
        }

# ---------------------------------------------------------------------------
# Utility Functions
# ---------------------------------------------------------------------------

def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    freq: dict[str, int] = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def is_dummy(value: str) -> bool:
    stripped = value.strip().lower()
    if stripped in DUMMY_VALUES:
        return True
    if len(set(stripped)) <= 2:
        return True
    if re.match(r'^[x\*\.]+$', stripped):
        return True
    if re.match(r'^(0+|1+|a+|test|example|placeholder|dummy|sample)$', stripped, re.IGNORECASE):
        return True
    return False


def mask_value(value: str) -> str:
    if len(value) <= MASK_VISIBLE_CHARS * 2:
        return value[:2] + "****"
    return value[:MASK_VISIBLE_CHARS] + "****" + value[-4:]

# ---------------------------------------------------------------------------
# Detection Engine
# ---------------------------------------------------------------------------

def detect_secrets(content: str, source_url: str) -> list[SecretFinding]:
    """
    Run all compiled patterns against content.
    Returns deduplicated findings, keeping highest severity per masked value.
    """
    raw_findings: list[SecretFinding] = []
    seen_raw: set[tuple[str, str]] = set()

    for service, cfg in PATTERNS.items():
        pattern = _COMPILED_PATTERNS.get(service)
        if pattern is None:
            continue

        try:
            matches = pattern.findall(content)
        except re.error:
            continue

        for raw_match in matches:
            value = (raw_match if isinstance(raw_match, str) else raw_match[0]).strip()
            if not value:
                continue

            min_len = cfg.get("min_length", 0)
            if min_len and len(value) < min_len:
                continue
            if is_dummy(value):
                continue
            if cfg.get("entropy_check") and len(value) >= MIN_KEY_LENGTH:
                if shannon_entropy(value) < MIN_ENTROPY:
                    continue

            dedup_key = (service, value[:20].lower())
            if dedup_key in seen_raw:
                continue
            seen_raw.add(dedup_key)

            raw_findings.append(SecretFinding(
                service=service,
                masked_value=mask_value(value),
                source_url=source_url,
                severity=cfg["severity"],
                category=cfg.get("category", "generic"),
                description=f"Possible exposed {service} found in page source.",
            ))

    # ---------------------------------------------------------------------------
    # Domain-aware false-positive suppression
    # ---------------------------------------------------------------------------
    # Some patterns match intentional, public values on the vendor's own domain.
    # e.g. Google API keys on google.com / googleapis.com are not secrets.
    _DOMAIN_SUPPRESSION: dict[str, list[str]] = {
        "Google API Key":   ["google.com", "googleapis.com", "gstatic.com"],
        "Firebase URL":     ["google.com", "firebase.google.com"],
        "Exposed OpenAI Endpoint": ["openai.com"],
        "Exposed Anthropic Endpoint": ["anthropic.com"],
    }

    from urllib.parse import urlparse as _urlparse
    source_host = _urlparse(source_url).hostname or ""

    raw_findings_filtered: list[SecretFinding] = []
    for f in raw_findings:
        suppressed_domains = _DOMAIN_SUPPRESSION.get(f.service, [])
        if any(source_host == d or source_host.endswith("." + d) for d in suppressed_domains):
            continue  # skip: vendor's own key on vendor's own domain
        raw_findings_filtered.append(f)
    raw_findings = raw_findings_filtered

    # Deduplicate by masked_value: keep highest severity
    best: dict[str, SecretFinding] = {}
    for f in raw_findings:
        existing = best.get(f.masked_value)
        if existing is None:
            best[f.masked_value] = f
        elif SEVERITY_ORDER.get(f.severity, 99) < SEVERITY_ORDER.get(existing.severity, 99):
            best[f.masked_value] = f

    return list(best.values())

# ---------------------------------------------------------------------------
# Top-Level Scanner
# ---------------------------------------------------------------------------

async def scan(
    url: str,
    *,
    timeout: int = DEFAULT_TIMEOUT,
    crawl_depth: int = DEFAULT_CRAWL_DEPTH,
    insecure: bool = False,
    concurrency: int = DEFAULT_MAX_CONCURRENT,
    pre_crawled: Optional[dict[str, Optional[str]]] = None,
) -> dict:
    """
    Run secret scanning across all crawled pages.

    Args:
        pre_crawled: Optional pre-crawled {url: body} dict to reuse (skips internal crawl).

    Returns:
        JSON-serializable dict: {target, scanned_urls, findings, errors}
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    result = SecretScanResult(target=url)
    semaphore = asyncio.Semaphore(concurrency)

    all_findings: list[SecretFinding] = []

    async with make_session(insecure=insecure, timeout=timeout) as session:
        if pre_crawled is not None:
            pages = pre_crawled
        else:
            pages = await crawl(
                session, url, semaphore,
                depth=min(crawl_depth, MAX_CRAWL_DEPTH),
                prioritize_js=True,
            )

        for page_url, body in pages.items():
            result.scanned_urls.append(page_url)
            if not body:
                continue
            page_findings = detect_secrets(body, page_url)
            all_findings.extend(page_findings)

    # Global deduplication across all pages
    seen_global: set[tuple[str, str, str]] = set()
    for f in all_findings:
        key = (f.service, f.masked_value, f.source_url)
        if key not in seen_global:
            seen_global.add(key)
            result.findings.append(f)

    return result.to_dict()

# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def main() -> None:
    target = os.environ.get("TARGET_URL", "").strip()
    if not target and len(sys.argv) > 1:
        target = sys.argv[1].strip()
    if not target:
        print(json.dumps({
            "error": "No target URL provided. Set TARGET_URL env var or pass as CLI argument."
        }))
        sys.exit(1)

    crawl_depth = min(
        int(os.environ.get("CRAWL_DEPTH", str(DEFAULT_CRAWL_DEPTH))),
        MAX_CRAWL_DEPTH,
    )
    insecure = os.environ.get("INSECURE", "").lower() in ("1", "true", "yes")
    result = asyncio.run(scan(target, crawl_depth=crawl_depth, insecure=insecure))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()