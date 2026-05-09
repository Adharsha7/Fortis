    
import asyncio
import aiohttp
import sys
import re
import time
import json
import argparse
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Set

# ── Terminal colours ──────────────────────────────────────
SEVERITY_COLOR = {
    "CRITICAL": "\033[91m", "HIGH": "\033[31m",
    "MEDIUM":   "\033[33m", "LOW":  "\033[34m", "INFO": "\033[37m",
}
RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
GREEN = "\033[92m"; CYAN = "\033[96m"

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

_SEM_LIMIT       = 6
_REQUEST_TIMEOUT = 10  

# ── Data models ───────────────────────────────────────────
@dataclass
class BOLAFinding:
    module:         str
    name:           str
    severity:       str
    description:    str
    endpoint:       str
    method:         str = "GET"
    evidence:       str = ""
    original_id:    str = ""
    tested_id:      str = ""
    recommendation: str = ""

@dataclass
class ScanResult:
    target:           str
    duration:         float = 0.0
    findings:         List[BOLAFinding] = field(default_factory=list)
    endpoints_tested: int = 0
    modules_run:      List[str] = field(default_factory=list)
    errors:           List[str] = field(default_factory=list)

# ── Target-specific endpoint lists ───────────────────────

# Core REST/API paths with numeric IDs
TARGET_ID_PATHS = [
    "/api/Users/{id}",
    "/api/Products/{id}",
    "/api/BasketItems/{id}",
    "/api/Feedbacks/{id}",
    "/api/Complaints/{id}",
    "/api/Recycles/{id}",
    "/api/Orders/{id}",
    "/api/Addresss/{id}",       # typo in schema — it's "Addresss"
    "/api/PrivacyRequests/{id}",
    "/rest/basket/{id}",
    "/rest/user/whoami",        # returns logged-in user — no ID needed
]

# Admin / privileged list endpoints (no ID — return all records)
TARGET_LIST_PATHS = [
    "/api/Users/",
    "/api/Products/",
    "/api/BasketItems/",
    "/api/Feedbacks/",
    "/api/Complaints/",
    "/api/Recycles/",
    "/api/Orders/",
    "/api/Addresss/",
    "/api/PrivacyRequests/",
    "/api/Deliverys/",
    "/api/Memories/",
    "/api/Quantitys/",
    "/api/SecurityAnswers/",
    "/api/SecurityQuestions/",
]

# Write-method targets
WRITE_PATHS = [
    "/api/Users/{id}",
    "/api/BasketItems/{id}",
    "/api/Feedbacks/{id}",
    "/api/Complaints/{id}",
    "/api/Addresss/{id}",
]

# Response field regex — covers the actual JSON schema
_DATA_FIELDS = re.compile(
    r'"(?:id|ID|email|username|name|role|password|token|BasketId|UserId|data|status|address)"',
    re.I,
)

# ── Shared HTTP helper ────────────────────────────────────
async def _fetch(session: aiohttp.ClientSession,
                 sem: asyncio.Semaphore,
                 url: str,
                 method: str = "GET",
                 headers: Optional[Dict] = None,
                 json_body=None,
                 token: Optional[str] = None) -> tuple:
    """Return (status, body_text, response_headers). Never raises."""
    h = {
        "User-Agent": "Mozilla/5.0 (BOLA-Scanner/3.0)",
        "Accept": "application/json, */*",
    }
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
            if json_body is not None:
                kw["json"] = json_body
            async with session.request(method, url, **kw) as r:
                body = await r.text(errors="ignore")
                return r.status, body, dict(r.headers)
    except asyncio.TimeoutError:
        return 0, "", {"_error": "timeout"}
    except aiohttp.ClientError as exc:
        return 0, "", {"_error": str(exc)}
    except Exception as exc:
        return 0, "", {"_error": str(exc)}

# ── Auto-login helper ─────────────────────────────────────
async def _login(session: aiohttp.ClientSession,
                 sem: asyncio.Semaphore,
                 base_url: str,
                 email: str,
                 password: str) -> Optional[str]:
    """POST to login endpoint, return JWT token or None."""
    url = base_url.rstrip("/") + "/rest/user/login"
    s, body, _ = await _fetch(
        session, sem, url, method="POST",
        json_body={"email": email, "password": password},
    )
    if s != 200:
        return None
    try:
        data = json.loads(body)
        return data.get("authentication", {}).get("token")
    except (json.JSONDecodeError, KeyError, AttributeError):
        return None

# ── Endpoint discovery ────────────────────────────────────
async def _discover_endpoints(session: aiohttp.ClientSession,
                               sem: asyncio.Semaphore,
                               base_url: str,
                               token: Optional[str]) -> List[str]:
    """
    Fetch the SPA bundle and extract /api/ and /rest/ paths.
    Falls back to the known static list if JS parsing yields nothing.
    """
    origin = base_url.rstrip("/")
    found: Set[str] = set()

    # 1. Fetch main page to find the JS bundle
    s, body, _ = await _fetch(session, sem, base_url, token=token)
    js_urls: List[str] = []
    if s == 200:
        for m in re.finditer(r'src=["\']([^"\']*\.js)["\']', body):
            js_urls.append(urljoin(base_url, m.group(1)))

    # 2. Scrape API paths from JS bundle(s)
    for js_url in js_urls[:5]:
        _, js_body, _ = await _fetch(session, sem, js_url)
        for m in re.finditer(
            r'["\'](/(?:api|rest)/[^"\'<>\s]{1,100})["\']', js_body
        ):
            path = m.group(1)
            # Skip paths with template literals / variables
            if "${" in path or "{{" in path:
                continue
            full = origin + path
            found.add(full)

    # 3. Always include known static paths
    for path in TARGET_ID_PATHS + TARGET_LIST_PATHS:
        found.add(origin + path.replace("{id}", "1"))

    return list(found)


# ══════════════════════════════════════════════════════════
#  MODULE 01 — ID Manipulation
#  Tests /api/Users/1, /api/BasketItems/1, etc.
# ══════════════════════════════════════════════════════════
async def module_01_id_manipulation(session, sem, base_url, token, token2,
                                     endpoints, findings, errors):
    origin = base_url.rstrip("/")
    test_ids = ["1", "2", "3", "100"]

    async def probe(path_tpl, test_id):
        url = origin + path_tpl.replace("{id}", test_id)
        s, body, _ = await _fetch(session, sem, url, token=token)
        if s not in (200, 201) or len(body) < 10:
            return

        # Must look like real data, not an HTML error page
        if "<html" in body.lower()[:200]:
            return
        if not _DATA_FIELDS.search(body):
            return

        # Cross-check: ID 0 or 99999 — if it also 200s with same size, it's
        # a wildcard route (false positive).
        s_invalid, body_invalid, _ = await _fetch(
            session, sem, origin + path_tpl.replace("{id}", "99999"), token=token
        )
        if s_invalid == 200 and abs(len(body) - len(body_invalid)) < 30:
            return  # Wildcard / not a real object store

        # Confirm endpoint requires auth (otherwise it's public — lower severity)
        s_unauth, _, _ = await _fetch(session, sem, url)
        severity = "HIGH" if s_unauth in (401, 403) else "MEDIUM"

        findings.append(BOLAFinding(
            module="01 ID Manipulation",
            name="BOLA — Direct Object Access by ID",
            severity=severity,
            description=(
                f"'{path_tpl}' returned data for ID={test_id} without "
                f"confirming the object belongs to the requesting user."
            ),
            endpoint=url,
            method="GET",
            original_id="<your_id>",
            tested_id=test_id,
            evidence=(
                f"HTTP {s} | Auth-required: {s_unauth in (401,403)} | "
                f"Body length: {len(body)}"
            ),
            recommendation=(
                "Derive the authorised user identity from the JWT on the server. "
                "Reject requests where the object's owner != authenticated user."
            ),
        ))

    tasks = [probe(p, tid) for p in TARGET_ID_PATHS if "{id}" in p
             for tid in test_ids]
    for coro in asyncio.as_completed(tasks):
        try:
            await coro
        except Exception as exc:
            errors.append(f"module_01: {exc}")


# ══════════════════════════════════════════════════════════
#  MODULE 02 — List Endpoints (no ID filter → dumps all records)
# ══════════════════════════════════════════════════════════
async def module_02_list_endpoints(session, sem, base_url, token, token2,
                                    endpoints, findings, errors):
    origin = base_url.rstrip("/")

    async def probe(path):
        url = origin + path
        s, body, _ = await _fetch(session, sem, url, token=token)
        if s != 200 or len(body) < 20:
            return
        if "<html" in body.lower()[:200]:
            return

        # API wraps lists in {"data": [...]}
        try:
            data = json.loads(body)
            records = data.get("data", data)
            if not isinstance(records, list) or len(records) == 0:
                return
            record_count = len(records)
        except (json.JSONDecodeError, AttributeError):
            # Fallback: check for array-like response
            if body.count('"id"') < 2:
                return
            record_count = body.count('"id"')

        # Check if endpoint is public (no token needed)
        s_unauth, body_unauth, _ = await _fetch(session, sem, url)
        auth_required = s_unauth in (401, 403)
        severity = "CRITICAL" if auth_required else "MEDIUM"

        findings.append(BOLAFinding(
            module="02 List Endpoints",
            name="BOLA — Unenforced List Endpoint Exposes All Records",
            severity=severity,
            description=(
                f"'{path}' returns all records ({record_count} objects) without "
                f"filtering to the authenticated user's own data."
            ),
            endpoint=url,
            method="GET",
            evidence=(
                f"HTTP {s} | Records returned: {record_count} | "
                f"Auth required: {auth_required}"
            ),
            recommendation=(
                "Filter list responses server-side using the authenticated "
                "user's identity from the JWT — never return all records to "
                "a non-admin user."
            ),
        ))

    tasks = [probe(p) for p in TARGET_LIST_PATHS]
    for coro in asyncio.as_completed(tasks):
        try:
            await coro
        except Exception as exc:
            errors.append(f"module_02: {exc}")


# ══════════════════════════════════════════════════════════
#  MODULE 03 — Cross-User Object Access (token vs token2)
#  Requires two valid JWTs to prove cross-account BOLA.
# ══════════════════════════════════════════════════════════
async def module_03_cross_user(session, sem, base_url, token, token2,
                                endpoints, findings, errors):
    if not token or not token2:
        return  # Need two accounts

    origin = base_url.rstrip("/")

    # First, discover what objects user-1 owns
    owned_ids: Dict[str, List[str]] = {}  # path_tpl -> [id, ...]

    async def find_owned(path_tpl):
        for oid in ["1", "2", "3", "4", "5"]:
            url = origin + path_tpl.replace("{id}", oid)
            s, body, _ = await _fetch(session, sem, url, token=token)
            if s == 200 and len(body) > 10 and not "<html" in body.lower()[:200]:
                if _DATA_FIELDS.search(body):
                    owned_ids.setdefault(path_tpl, []).append(oid)

    await asyncio.gather(*[find_owned(p) for p in TARGET_ID_PATHS if "{id}" in p])

    # Now try accessing user-1's objects with user-2's token
    async def probe_cross(path_tpl, oid):
        url = origin + path_tpl.replace("{id}", oid)
        s, body, _ = await _fetch(session, sem, url, token=token2)
        if s == 200 and _DATA_FIELDS.search(body):
            findings.append(BOLAFinding(
                module="03 Cross-User Access",
                name="BOLA — Object of User A Accessible by User B",
                severity="CRITICAL",
                description=(
                    f"Object at '{path_tpl}' (ID={oid}) owned by User 1 "
                    f"is fully readable using User 2's JWT — no ownership check."
                ),
                endpoint=url,
                method="GET",
                original_id=f"user1_id={oid}",
                tested_id=f"user2_token+id={oid}",
                evidence=f"HTTP {s} returned data with token2",
                recommendation=(
                    "Server must compare the object's owner field against "
                    "the authenticated user in the JWT on every request."
                ),
            ))

    tasks = [
        probe_cross(p, oid)
        for p, ids in owned_ids.items()
        for oid in ids
    ]
    for coro in asyncio.as_completed(tasks):
        try:
            await coro
        except Exception as exc:
            errors.append(f"module_03: {exc}")


# ══════════════════════════════════════════════════════════
#  MODULE 04 — PUT / PATCH / DELETE on other users' objects
# ══════════════════════════════════════════════════════════
async def module_04_write_methods(session, sem, base_url, token, token2,
                                   endpoints, findings, errors):
    if not token:
        return
    origin = base_url.rstrip("/")
    test_payload = {"_bola_test": True}

    async def probe(path_tpl, method, test_id):
        url = origin + path_tpl.replace("{id}", test_id)
        s, body, _ = await _fetch(
            session, sem, url, method=method,
            json_body=test_payload, token=token
        )
        # 200/204 = success; 400/422 with body = server processed it (validation error)
        if s not in (200, 201, 204) and not (
            s in (400, 422) and len(body) > 5
        ):
            return

        # Confirm unauthenticated request is blocked
        s_unauth, _, _ = await _fetch(
            session, sem, url, method=method, json_body=test_payload
        )
        if s_unauth not in (401, 403):
            return  # Public endpoint — not a BOLA finding

        findings.append(BOLAFinding(
            module="04 Write Methods",
            name=f"BOLA — {method} on Another User's Object",
            severity="CRITICAL",
            description=(
                f"Authenticated {method} to '{path_tpl}' with ID={test_id} "
                f"was accepted. The server did not verify object ownership."
            ),
            endpoint=url,
            method=method,
            tested_id=test_id,
            evidence=f"HTTP {s} with token | HTTP {s_unauth} without token",
            recommendation=(
                "Verify that the object's owner matches the authenticated user "
                "before processing any write (PUT/PATCH/DELETE) operation."
            ),
        ))

    tasks = [
        probe(p, m, tid)
        for p in WRITE_PATHS
        for m in ("PUT", "PATCH", "DELETE")
        for tid in ["2", "3"]
    ]
    for coro in asyncio.as_completed(tasks):
        try:
            await coro
        except Exception as exc:
            errors.append(f"module_04: {exc}")


# ══════════════════════════════════════════════════════════
#  MODULE 05 — Query Parameter Tampering (user_id, id, etc.)
# ══════════════════════════════════════════════════════════
async def module_05_param_tampering(session, sem, base_url, token, token2,
                                     endpoints, findings, errors):
    id_params = ["user_id", "userId", "UserId", "account_id", "id", "uid"]
    test_vals  = ["1", "2", "100"]

    async def probe(endpoint, param, val):
        parsed = urlparse(endpoint)
        qs = parse_qs(parsed.query)
        original_val = qs.get(param, [None])[0]
        if original_val == val:
            return
        qs[param] = [val]
        new_query = urlencode(qs, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))
        s, body, _ = await _fetch(session, sem, test_url, token=token)
        if s != 200 or len(body) < 20 or "<html" in body.lower()[:200]:
            return
        if not _DATA_FIELDS.search(body):
            return
        findings.append(BOLAFinding(
            module="05 Param Tampering",
            name=f"BOLA — Query Param '{param}' Override",
            severity="HIGH",
            description=(
                f"Setting '{param}={val}' on '{parsed.path}' returned data "
                f"without server-side ownership validation."
            ),
            endpoint=test_url,
            method="GET",
            original_id=f"{param}={original_id}" if (original_id := original_val) else "unset",
            tested_id=f"{param}={val}",
            evidence=f"HTTP {s} | Data fields present | Length={len(body)}",
            recommendation=(
                "Never derive user identity from query parameters. "
                "Always use the authenticated JWT on the server side."
            ),
        ))

    # Only probe endpoints that already have query strings, plus the
    # API list endpoints (which accept ?filter= style params)
    origin = base_url.rstrip("/")
    extra = [origin + p for p in TARGET_LIST_PATHS]
    all_eps = list(set(endpoints + extra))[:40]

    tasks = [probe(ep, p, v) for ep in all_eps for p in id_params for v in test_vals]
    for coro in asyncio.as_completed(tasks):
        try:
            await coro
        except Exception as exc:
            errors.append(f"module_05: {exc}")


# ══════════════════════════════════════════════════════════
#  MODULE 06 — Basket / Cart BOLA
#  /rest/basket/{id}  — each user should only see their basket
# ══════════════════════════════════════════════════════════
async def module_06_basket_bola(session, sem, base_url, token, token2,
                                 endpoints, findings, errors):
    origin = base_url.rstrip("/")

    async def probe(basket_id):
        url = f"{origin}/rest/basket/{basket_id}"
        s, body, _ = await _fetch(session, sem, url, token=token)
        if s != 200 or len(body) < 10 or "<html" in body.lower()[:200]:
            return

        try:
            data = json.loads(body)
            basket = data.get("data", data)
            # Must have basket fields to be genuine
            if not any(k in str(basket) for k in ("BasketItem", "Products", "id")):
                return
        except (json.JSONDecodeError, TypeError):
            return

        s_unauth, _, _ = await _fetch(session, sem, url)
        auth_required = s_unauth in (401, 403)

        findings.append(BOLAFinding(
            module="06 Basket BOLA",
            name="BOLA — Shopping Basket Accessible by Arbitrary ID",
            severity="HIGH" if auth_required else "MEDIUM",
            description=(
                f"/rest/basket/{basket_id} returns basket contents. "
                f"Any authenticated user can enumerate other users' baskets."
            ),
            endpoint=url,
            method="GET",
            tested_id=str(basket_id),
            evidence=(
                f"HTTP {s} | Auth required: {auth_required} | "
                f"Body length: {len(body)}"
            ),
            recommendation=(
                "Validate on the server that the basket's UserId matches "
                "the authenticated user's ID from the JWT before returning data."
            ),
        ))

    tasks = [probe(i) for i in range(1, 8)]
    for coro in asyncio.as_completed(tasks):
        try:
            await coro
        except Exception as exc:
            errors.append(f"module_06: {exc}")


# ══════════════════════════════════════════════════════════
#  MODULE 07 — Admin endpoint access by regular user
# ══════════════════════════════════════════════════════════
async def module_07_admin_access(session, sem, base_url, token, token2,
                                  endpoints, findings, errors):
    origin = base_url.rstrip("/")
    admin_paths = [
        "/api/Users/",          # full user list (admin only in theory)
        "/api/SecurityAnswers/",
        "/api/PrivacyRequests/",
        "/api/Complaints/",
        "/api/Recycles/",
        "/rest/admin/application-configuration",
        "/rest/admin/application-version",
        "/rest/user/authentication-details",
        "/administration",
    ]

    async def probe(path):
        url = origin + path
        s, body, _ = await _fetch(session, sem, url, token=token)
        if s != 200 or len(body) < 15:
            return
        if "<html" in body.lower()[:200] and path not in ("/administration",):
            return

        s_unauth, _, _ = await _fetch(session, sem, url)
        # If publicly accessible, it's a separate issue — still flag
        already_public = s_unauth == 200

        findings.append(BOLAFinding(
            module="07 Admin Access",
            name="BOLA — Privileged Endpoint Reachable by Regular User",
            severity="CRITICAL",
            description=(
                f"Admin/privileged path '{path}' returned HTTP {s} for a "
                f"regular user token. {'Also publicly accessible.' if already_public else ''}"
            ),
            endpoint=url,
            method="GET",
            evidence=(
                f"HTTP {s} with user token | "
                f"HTTP {s_unauth} without token"
            ),
            recommendation=(
                "Add role-based access control (RBAC) middleware. "
                "Check the user's 'role' claim in the JWT before serving admin data."
            ),
        ))

    tasks = [probe(p) for p in admin_paths]
    for coro in asyncio.as_completed(tasks):
        try:
            await coro
        except Exception as exc:
            errors.append(f"module_07: {exc}")


# ══════════════════════════════════════════════════════════
#  MODULE 08 — Sequential ID Enumeration
# ══════════════════════════════════════════════════════════
async def module_08_enumeration(session, sem, base_url, token, token2,
                                 endpoints, findings, errors):
    origin = base_url.rstrip("/")
    probe_paths = ["/api/Users/{id}", "/api/BasketItems/{id}",
                   "/api/Feedbacks/{id}", "/rest/basket/{id}"]
    ids_to_test = list(range(1, 8))

    hits: Dict[str, List[int]] = {}

    async def probe(path_tpl, oid):
        url = origin + path_tpl.replace("{id}", str(oid))
        s, body, _ = await _fetch(session, sem, url, token=token)
        if s == 200 and len(body) > 20 and not "<html" in body.lower()[:200]:
            if _DATA_FIELDS.search(body):
                hits.setdefault(path_tpl, []).append(oid)

    tasks = [probe(p, i) for p in probe_paths for i in ids_to_test]
    for coro in asyncio.as_completed(tasks):
        try:
            await coro
        except Exception as exc:
            errors.append(f"module_08: {exc}")

    for path_tpl, found_ids in hits.items():
        if len(found_ids) >= 3:
            findings.append(BOLAFinding(
                module="08 Enumeration",
                name="BOLA — Sequential ID Enumeration Confirmed",
                severity="HIGH",
                description=(
                    f"'{path_tpl}' returns valid objects for IDs "
                    f"{found_ids[:5]} — sequential enumeration is trivial."
                ),
                endpoint=origin + path_tpl.replace("{id}", str(found_ids[0])),
                method="GET",
                original_id=str(found_ids[0]),
                tested_id=f"1–{found_ids[-1]}",
                evidence=f"{len(found_ids)} consecutive IDs returned HTTP 200",
                recommendation=(
                    "Switch to UUIDs (v4). Add per-user rate limiting. "
                    "Always enforce ownership checks regardless of ID format."
                ),
            ))


# ══════════════════════════════════════════════════════════
#  ORCHESTRATOR
# ══════════════════════════════════════════════════════════
async def run_scanner(target_url: str,
                      token: Optional[str] = None,
                      token2: Optional[str] = None,
                      email: Optional[str] = None,
                      password: Optional[str] = None,
                      email2: Optional[str] = None,
                      password2: Optional[str] = None) -> ScanResult:
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url
    target_url = target_url.rstrip("/")

    result = ScanResult(target=target_url)
    sem = asyncio.Semaphore(_SEM_LIMIT)
    connector = aiohttp.TCPConnector(ssl=False, limit=_SEM_LIMIT)

    async with aiohttp.ClientSession(connector=connector) as session:
        # Auto-login if credentials provided
        if email and password and not token:
            print(f"  {CYAN}⟳  Logging in as {email} …{RESET}")
            token = await _login(session, sem, target_url, email, password)
            if token:
                print(f"  {GREEN}✅  Token obtained for user 1{RESET}")
            else:
                print(f"  \033[91m✗   Login failed for {email}{RESET}")

        if email2 and password2 and not token2:
            print(f"  {CYAN}⟳  Logging in as {email2} …{RESET}")
            token2 = await _login(session, sem, target_url, email2, password2)
            if token2:
                print(f"  {GREEN}✅  Token obtained for user 2{RESET}")
            else:
                print(f"  \033[91m✗   Login failed for {email2}{RESET}")

        start = time.perf_counter()

        print(f"  {CYAN}⟳  Discovering endpoints …{RESET}")
        endpoints = await _discover_endpoints(session, sem, target_url, token)
        result.endpoints_tested = len(endpoints)
        print(f"  {GREEN}✅  {len(endpoints)} endpoints collected{RESET}")

        findings: List[BOLAFinding] = []

        modules = [
            ("01 ID Manipulation",    module_01_id_manipulation),
            ("02 List Endpoints",     module_02_list_endpoints),
            ("03 Cross-User Access",  module_03_cross_user),
            ("04 Write Methods",      module_04_write_methods),
            ("05 Param Tampering",    module_05_param_tampering),
            ("06 Basket BOLA",        module_06_basket_bola),
            ("07 Admin Access",       module_07_admin_access),
            ("08 Enumeration",        module_08_enumeration),
        ]

        BATCH = 3
        for i in range(0, len(modules), BATCH):
            batch = modules[i:i + BATCH]
            tasks = []
            for name, fn in batch:
                result.modules_run.append(name)
                print(f"  {DIM}⟳  Running {name} …{RESET}")
                tasks.append(
                    fn(session, sem, target_url, token, token2,
                       endpoints, findings, result.errors)
                )
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for (name, _), res in zip(batch, results):
                if isinstance(res, Exception):
                    result.errors.append(f"{name}: {res}")

        result.duration = time.perf_counter() - start

        # Deduplicate
        seen: Set[tuple] = set()
        for f in findings:
            key = (f.endpoint[:100], f.tested_id, f.name[:50])
            if key not in seen:
                seen.add(key)
                result.findings.append(f)

    result.findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    return result


# ══════════════════════════════════════════════════════════
#  REPORT
# ══════════════════════════════════════════════════════════
def print_report(result: ScanResult) -> None:
    line = "═" * 72
    print(f"\n{BOLD}{line}{RESET}")
    print(f"{BOLD}  BOLA / IDOR SCAN REPORT{RESET}")
    print(f"{BOLD}{line}{RESET}")
    print(f"  Target           : {result.target}")
    print(f"  Scan Duration    : {result.duration:.2f}s")
    print(f"  Endpoints Tested : {result.endpoints_tested}")
    print(f"  Modules Run      : {len(result.modules_run)}/8")
    print(f"  Findings         : {len(result.findings)}")
    print(f"{line}\n")

    if not result.findings:
        print(f"  {GREEN}✅  No BOLA vulnerabilities detected.{RESET}\n")
        print("  Tip: Provide --email / --password (or --token) for authenticated scanning.\n")
    else:
        counts: Dict[str, int] = {}
        for f in result.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        print(f"  {BOLD}Severity Summary:{RESET}")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if sev in counts:
                color = SEVERITY_COLOR[sev]
                bar = "█" * min(counts[sev] * 3, 36)
                print(f"    {color}{sev:<10}{RESET}  {bar}  {counts[sev]}")
        print()
        for i, f in enumerate(result.findings, 1):
            color = SEVERITY_COLOR.get(f.severity, "")
            print(f"  {BOLD}[{i:02d}] {color}{f.severity}{RESET}{BOLD}  [{f.module}]  {f.name}{RESET}")
            print(f"       Endpoint    : [{f.method}] {f.endpoint}")
            print(f"       Description : {f.description}")
            if f.original_id: print(f"       Original ID : {f.original_id}")
            if f.tested_id:   print(f"       Tested ID   : {f.tested_id}")
            if f.evidence:    print(f"       Evidence    : {f.evidence}")
            if f.recommendation: print(f"       Fix         : {f.recommendation}")
            print()

    if result.errors:
        print(f"  {DIM}Scan errors ({len(result.errors)}):{RESET}")
        for e in result.errors[:10]:
            print(f"     • {e}")
        print()
    print(line)


# ══════════════════════════════════════════════════════════
#  STANDARD FORTIS scan() INTERFACE
# ══════════════════════════════════════════════════════════
async def scan(
    target: str,
    crawl_depth: int = 2,
    insecure: bool = False,
    pre_crawled: dict | None = None,
) -> dict:
    token = token2 = email = password = email2 = password2 = None
    if isinstance(pre_crawled, dict):
        token    = pre_crawled.get("token")
        token2   = pre_crawled.get("token2")
        email    = pre_crawled.get("email")
        password = pre_crawled.get("password")
        email2   = pre_crawled.get("email2")
        password2 = pre_crawled.get("password2")
    try:
        result = await run_scanner(
            target, token=token, token2=token2,
            email=email, password=password,
            email2=email2, password2=password2,
        )
        return {
            "target": result.target,
            "findings": [
                {
                    "check":          f.name,
                    "severity":       f.severity,
                    "description":    f.description,
                    "source_url":     f.endpoint,
                    "evidence":       f.evidence or f"method={f.method} tested_id={f.tested_id}",
                    "recommendation": f.recommendation,
                    "category":       f.module,
                    "method":         f.method,
                }
                for f in result.findings
            ],
            "errors": result.errors,
            "meta": {
                "duration":         round(result.duration, 2),
                "endpoints_tested": result.endpoints_tested,
                "modules_run":      len(result.modules_run),
            },
        }
    except Exception as exc:
        return {"target": target, "findings": [], "errors": [str(exc)]}


# ══════════════════════════════════════════════════════════
#  STANDALONE ENTRY POINT
# ══════════════════════════════════════════════════════════
async def _main():
    parser = argparse.ArgumentParser(
        description="BOLA/IDOR Scanner (8 Modules)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  # Unauthenticated scan (limited coverage)\n"
            "  python bola.py https://target.example.com\n\n"
            "  # Authenticated with one account\n"
            "  python bola.py https://target.example.com "
            "--email user@example.com --password ncc-1701\n\n"
            "  # Cross-user BOLA test (two accounts)\n"
            "  python bola.py https://target.example.com "
            "--email u1@example.com --password pass1 "
            "--email2 u2@example.com --password2 pass2\n\n"
            "  # Pre-existing tokens\n"
            "  python bola.py https://target.example.com "
            "--token eyJ... --token2 eyJ..."
        ),
    )
    parser.add_argument("url",        help="Target base URL")
    parser.add_argument("--token",    default=None, help="User 1 JWT")
    parser.add_argument("--token2",   default=None, help="User 2 JWT (cross-user tests)")
    parser.add_argument("--email",    default=None, help="User 1 email (auto-login)")
    parser.add_argument("--password", default=None, help="User 1 password (auto-login)")
    parser.add_argument("--email2",   default=None, help="User 2 email (auto-login)")
    parser.add_argument("--password2",default=None, help="User 2 password (auto-login)")
    args = parser.parse_args()

    print(f"\n  {BOLD}{'═'*60}{RESET}")
    print(f"  {BOLD}BOLA / IDOR Scanner{RESET}")
    print(f"  {BOLD}8 Modules  |  Target-Specific Endpoints{RESET}")
    print(f"  {BOLD}{'═'*60}{RESET}")
    print(f"  Target  : {args.url}")
    print(f"  Token 1 : {'✅ provided' if args.token  else ('🔑 via login' if args.email  else '⚠️  none')}")
    print(f"  Token 2 : {'✅ provided' if args.token2 else ('🔑 via login' if args.email2 else '⚠️  none (cross-user tests skipped)')}")

    result = await run_scanner(
        args.url,
        token=args.token, token2=args.token2,
        email=args.email, password=args.password,
        email2=args.email2, password2=args.password2,
    )
    print_report(result)


if __name__ == "__main__":
    asyncio.run(_main())