"""
Business Logic Vulnerability Scanner
======================================
Detects flaws in application business rules that security scanners miss.

What this scanner does:
  ✅ Price/amount tampering (negative prices, zero cost, overflow)
  ✅ Negative quantity attacks (negative items in cart)
  ✅ Coupon/discount abuse (reuse, stacking, negative discount)
  ✅ Payment step skipping (access order confirmation without paying)
  ✅ Privilege escalation via role parameter manipulation
  ✅ Balance/credit manipulation (negative transfer, overflow)
  ✅ Race condition detection (concurrent requests on limited resources)
  ✅ Limit bypass (exceed max purchase quantity, file size, API limits)
  ✅ Workflow bypass (skip required steps)
  ✅ Free item exploitation (0.00 price acceptance)
  ✅ Async concurrent scanning

Install:  pip install aiohttp
Usage:    python business_logic_scanner.py <url>
"""

import asyncio, aiohttp, sys, re, time, argparse, json
from urllib.parse import urlparse, urljoin
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple

BOLD="\033[1m"; RESET="\033[0m"; GREEN="\033[92m"; DIM="\033[2m"
SEV_COLOR={"CRITICAL":"\033[91m","HIGH":"\033[31m","MEDIUM":"\033[33m","LOW":"\033[34m","INFO":"\033[37m"}

@dataclass
class Finding:
    name: str; severity: str; description: str
    endpoint: str; method: str = "POST"
    evidence: str = ""; param: str = ""
    recommendation: str = ""

@dataclass
class ScanResult:
    target: str; duration: float = 0.0
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

# ── Endpoint patterns ─────────────────────────────────────
CART_ENDPOINTS = [
    "/api/v1/cart", "/api/cart", "/cart",
    "/api/v1/basket", "/api/basket",
    "/api/v1/order/items", "/api/order/items",
]

ORDER_ENDPOINTS = [
    "/api/v1/orders", "/api/orders",
    "/api/v1/checkout", "/api/checkout",
    "/api/v1/purchase", "/api/purchase",
    "/api/v1/buy", "/api/buy",
]

PAYMENT_ENDPOINTS = [
    "/api/v1/payment", "/api/payment",
    "/api/v1/payments", "/api/payments",
    "/api/v1/checkout/pay", "/api/checkout/pay",
    "/api/v1/order/pay", "/api/order/pay",
    "/payment/process", "/checkout/complete",
]

COUPON_ENDPOINTS = [
    "/api/v1/coupon/apply",  "/api/coupon/apply",
    "/api/v1/discount/apply","/api/discount/apply",
    "/api/v1/promo/apply",   "/api/promo/apply",
    "/api/v1/voucher/apply", "/api/voucher/apply",
    "/apply-coupon",         "/apply-discount",
]

TRANSFER_ENDPOINTS = [
    "/api/v1/transfer",      "/api/transfer",
    "/api/v1/wallet/transfer","/api/wallet/transfer",
    "/api/v1/send",          "/api/send",
    "/api/v1/payment/send",  "/api/v1/balance/transfer",
]

REGISTER_ENDPOINTS = [
    "/api/v1/register", "/api/register",
    "/api/v1/signup",   "/api/signup",
    "/register",        "/signup",
    "/api/v1/user",     "/api/user",
    "/api/v1/users",    "/api/users",
]

PROFILE_ENDPOINTS = [
    "/api/v1/profile",  "/api/profile",
    "/api/v1/user/me",  "/api/user/me",
    "/api/v1/me",       "/api/me",
    "/api/v1/account",  "/api/account",
    "/api/v1/users/1",  "/api/users/1",
]

WORKFLOW_STEPS = [
    # Checkout flow
    ["/api/v1/cart",
     "/api/v1/checkout/initiate",
     "/api/v1/checkout/payment",
     "/api/v1/checkout/confirm",
     "/api/v1/orders/complete"],
    # Subscription
    ["/api/v1/subscription/trial",
     "/api/v1/subscription/select-plan",
     "/api/v1/subscription/payment",
     "/api/v1/subscription/activate"],
]

async def fetch(session, url, method="POST", data=None, token=None,
                headers_extra=None):
    try:
        h = {"User-Agent":"Mozilla/5.0","Content-Type":"application/json","Accept":"*/*"}
        if token: h["Authorization"] = f"Bearer {token}"
        if headers_extra: h.update(headers_extra)
        kw = dict(headers=h, ssl=False, allow_redirects=True,
                  timeout=aiohttp.ClientTimeout(total=8))
        if data is not None:
            if method in ("POST","PUT","PATCH"): kw["json"] = data
        async with session.request(method, url, **kw) as r:
            body = await r.text(errors="ignore")
            return r.status, body, dict(r.headers)
    except: return 0, "", {}

def looks_successful(s, body):
    """Heuristic: did the server accept the request?"""
    if s in (200, 201, 202): return True
    if s == 400: return False
    body_l = body.lower()
    success_words = ["success","created","accepted","processed","confirmed","ok"]
    error_words   = ["error","invalid","failed","rejected","denied","negative","must be"]
    hits_success = sum(1 for w in success_words if w in body_l)
    hits_error   = sum(1 for w in error_words   if w in body_l)
    return hits_success > hits_error

def add(findings, name, severity, description, endpoint, method="POST",
        evidence="", param="", recommendation=""):
    findings.append(Finding(
        name=name, severity=severity, description=description,
        endpoint=endpoint, method=method, evidence=evidence,
        param=param, recommendation=recommendation,
    ))

# ── Check 1: Price / Amount Tampering ────────────────────
async def check_price_tampering(session, origin, findings, token):
    tamper_payloads = [
        ({"product_id":"1","quantity":1,"price":0.00},     "Zero price"),
        ({"product_id":"1","quantity":1,"price":-1.00},    "Negative price"),
        ({"product_id":"1","quantity":1,"price":0.001},    "Fractional price"),
        ({"product_id":"1","quantity":1,"price":0.00000001},"Near-zero price"),
        ({"product_id":"1","quantity":1,"price":999999999}, "Overflow price"),
        ({"items":[{"id":"1","price":0,"qty":1}]},         "Cart item zero price"),
        ({"items":[{"id":"1","price":-10,"qty":1}]},       "Cart item negative price"),
        ({"amount":0},                                      "Zero amount"),
        ({"amount":-100},                                   "Negative amount"),
        ({"total":0.00},                                    "Zero total"),
    ]

    for path in CART_ENDPOINTS + ORDER_ENDPOINTS + PAYMENT_ENDPOINTS:
        ep = f"{origin}{path}"
        for payload, label in tamper_payloads[:5]:
            s, body, _ = await fetch(session, ep, data=payload, token=token)
            if looks_successful(s, body) and s not in (404, 405, 0):
                add(findings, f"Price/Amount Tampering: {label}", "CRITICAL",
                    f"Endpoint '{path}' accepted a tampered price ({label}). "
                    "An attacker may be able to purchase items for free or negative cost.",
                    ep, evidence=f"Payload: {payload} | HTTP {s}",
                    recommendation="Validate all price/amount values server-side from your database. "
                    "Never trust client-supplied prices.")
                break

# ── Check 2: Negative Quantity ────────────────────────────
async def check_negative_quantity(session, origin, findings, token):
    neg_qty_payloads = [
        {"product_id":"1","quantity":-1},
        {"product_id":"1","quantity":-100},
        {"quantity":-1,"item_id":"1"},
        {"items":[{"id":"1","qty":-1}]},
        {"cart":[{"product_id":"1","quantity":-99999}]},
    ]

    for path in CART_ENDPOINTS + ORDER_ENDPOINTS:
        ep = f"{origin}{path}"
        for payload in neg_qty_payloads[:3]:
            s, body, _ = await fetch(session, ep, data=payload, token=token)
            if looks_successful(s, body) and s not in (404, 405, 0):
                add(findings, "Negative Quantity Accepted", "HIGH",
                    f"Endpoint '{path}' accepted a negative quantity. "
                    "This may allow credit manipulation or inventory bypass.",
                    ep, evidence=f"Payload: {payload} | HTTP {s}",
                    recommendation="Enforce quantity > 0 server-side. Reject zero or negative quantities.")
                break

# ── Check 3: Coupon / Discount Abuse ─────────────────────
async def check_coupon_abuse(session, origin, findings, token):
    coupon_payloads = [
        ({"coupon":"SAVE100","order_id":"1"},       "100% discount coupon"),
        ({"coupon":"FREE","order_id":"1"},           "FREE coupon"),
        ({"discount_code":"TEST100"},               "Test discount code"),
        ({"coupon":"INVALID","discount":-100},      "Negative discount amount"),
        ({"coupon":"SAVE10","coupon2":"SAVE10"},     "Coupon stacking"),
        ({"coupon":"ADMIN","discount":100,"order_id":"1"}, "Admin coupon"),
        ({"coupon":{"$gt":""}},                     "NoSQL injection in coupon"),
        ({"coupon":"A"*500},                        "Coupon overflow"),
    ]

    for path in COUPON_ENDPOINTS:
        ep = f"{origin}{path}"
        for payload, label in coupon_payloads[:5]:
            s, body, _ = await fetch(session, ep, data=payload, token=token)
            if looks_successful(s, body) and s not in (404, 405, 0):
                add(findings, f"Coupon/Discount Abuse: {label}", "HIGH",
                    f"Coupon endpoint '{path}' accepted suspicious payload ({label}).",
                    ep, evidence=f"Payload: {payload} | HTTP {s}",
                    recommendation="Validate coupons server-side against a database. "
                    "One-time use coupons must be marked as used atomically. "
                    "Reject negative discount values.")
                break

# ── Check 4: Balance / Transfer Manipulation ─────────────
async def check_balance_manipulation(session, origin, findings, token):
    transfer_payloads = [
        ({"from_account":"1","to_account":"2","amount":-100},  "Negative transfer (reverse money flow)"),
        ({"amount":0,"to":"attacker"},                         "Zero amount transfer"),
        ({"amount":99999999999},                               "Overflow amount"),
        ({"from":"victim_id","amount":1000},                   "Transfer from another user"),
        ({"amount":0.000001},                                  "Micro-transaction abuse"),
    ]

    for path in TRANSFER_ENDPOINTS:
        ep = f"{origin}{path}"
        for payload, label in transfer_payloads:
            s, body, _ = await fetch(session, ep, data=payload, token=token)
            if looks_successful(s, body) and s not in (404, 405, 0):
                add(findings, f"Balance Manipulation: {label}", "CRITICAL",
                    f"Transfer endpoint '{path}' accepted suspicious payload: {label}.",
                    ep, evidence=f"Payload: {payload} | HTTP {s}",
                    recommendation="Validate transfer amounts server-side. "
                    "Reject negative/zero amounts. Use database transactions for atomicity.")
                break

# ── Check 5: Privilege Escalation via Role Param ─────────
async def check_role_escalation(session, origin, findings, token):
    role_payloads = [
        ({"role":"admin"},                         "role=admin"),
        ({"role":"superuser"},                     "role=superuser"),
        ({"is_admin":True},                        "is_admin=true"),
        ({"admin":True},                           "admin=true"),
        ({"user_type":"admin"},                    "user_type=admin"),
        ({"account_type":"premium"},               "account_type=premium"),
        ({"permissions":["admin","superuser"]},    "permissions=[admin]"),
        ({"subscription":"enterprise"},            "subscription=enterprise"),
        ({"plan":"unlimited"},                     "plan=unlimited"),
        ({"role":"admin","verified":True,"active":True}, "Full admin profile"),
    ]

    for path in REGISTER_ENDPOINTS + PROFILE_ENDPOINTS:
        ep  = f"{origin}{path}"
        mth = "POST" if "register" in path or "signup" in path else "PATCH"
        for payload, label in role_payloads[:6]:
            s, body, _ = await fetch(session, ep, method=mth,
                                      data=payload, token=token)
            if looks_successful(s, body) and s not in (404, 405, 0):
                # Try to verify escalation by checking profile
                for check_path in ["/api/v1/me","/api/me","/api/v1/profile"]:
                    cs, cb, _ = await fetch(session, f"{origin}{check_path}",
                                             method="GET", token=token)
                    if cs == 200 and "admin" in cb.lower():
                        add(findings, f"Privilege Escalation via '{label}'", "CRITICAL",
                            f"Successfully escalated privileges by sending '{label}' "
                            f"in {mth} request to '{path}'.",
                            ep, method=mth,
                            evidence=f"Payload: {payload} | HTTP {s} | Profile shows admin",
                            recommendation="Never allow users to set their own role/permission fields. "
                            "Derive roles server-side from auth token only.")
                        return
                add(findings, f"Potential Role Escalation via '{label}'", "HIGH",
                    f"Endpoint '{path}' accepted a role-modification payload ({label}). "
                    "Server may not be filtering privilege fields.",
                    ep, method=mth,
                    evidence=f"Payload: {payload} | HTTP {s}",
                    recommendation="Ignore role/permission fields from user input. "
                    "Use server-side role assignment only.")
                break

# ── Check 6: Race Condition (Limited Resource) ────────────
async def check_race_condition(session, origin, findings, token):
    """Send concurrent requests to detect race conditions on limited resources."""
    race_endpoints = [
        ("/api/v1/coupon/apply",  {"coupon":"ONCE","order_id":"1"}),
        ("/api/coupon/apply",     {"coupon":"ONCE","order_id":"1"}),
        ("/api/v1/redeem",        {"voucher":"REDEEM1","user_id":"1"}),
        ("/api/v1/claim",         {"promo":"CLAIM1"}),
        ("/api/v1/gift/claim",    {"code":"GIFT1"}),
        ("/api/v1/referral/claim",{"code":"REF1"}),
    ]

    CONCURRENCY = 10  # Send 10 simultaneous requests

    for path, payload in race_endpoints:
        ep = f"{origin}{path}"
        # First check the endpoint exists
        s0, _, _ = await fetch(session, ep, data=payload, token=token)
        if s0 in (0, 404, 405): continue

        # Fire 10 concurrent requests
        tasks = [fetch(session, ep, data=payload, token=token)
                 for _ in range(CONCURRENCY)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        successes = [r for r in results
                     if isinstance(r, tuple) and r[0] in (200, 201)]

        if len(successes) >= 2:
            add(findings, f"Race Condition on '{path}'", "HIGH",
                f"{len(successes)} of {CONCURRENCY} concurrent requests succeeded on "
                f"'{path}'. A rate-limited or one-time resource may be claimable multiple times.",
                ep, evidence=f"{CONCURRENCY} concurrent requests | {len(successes)} succeeded",
                recommendation="Use database-level locking (SELECT FOR UPDATE) or atomic operations. "
                "Implement idempotency keys for one-time actions.")
            break

# ── Check 7: Limit Bypass ─────────────────────────────────
async def check_limit_bypass(session, origin, findings, token):
    limit_tests = [
        # Max quantity bypass
        (CART_ENDPOINTS[:3],
         [{"product_id":"1","quantity":9999999},
          {"product_id":"1","quantity":2147483648},   # INT_MAX+1
          {"product_id":"1","quantity":1e308}],       # float overflow
         "Max quantity bypass"),
        # Free tier limit bypass
        (ORDER_ENDPOINTS[:2],
         [{"items_count":9999},
          {"bulk":True,"quantity":99999}],
         "Free tier limit bypass"),
    ]

    for endpoints, payloads, label in limit_tests:
        for path in endpoints:
            ep = f"{origin}{path}"
            for payload in payloads:
                s, body, _ = await fetch(session, ep, data=payload, token=token)
                if looks_successful(s, body) and s not in (404, 405, 0):
                    add(findings, f"Business Logic Limit Bypass: {label}", "MEDIUM",
                        f"Endpoint '{path}' accepted an out-of-bounds value: {label}.",
                        ep, evidence=f"Payload: {json.dumps(payload)[:80]} | HTTP {s}",
                        recommendation="Enforce min/max bounds on all numeric inputs server-side. "
                        "Validate against business rules, not just data types.")
                    break

# ── Check 8: Workflow Step Bypass ────────────────────────
async def check_workflow_bypass(session, origin, findings, token):
    for workflow in WORKFLOW_STEPS:
        for i, step in enumerate(workflow):
            if i == 0: continue  # skip first step
            ep = f"{origin}{step}"
            s, body, _ = await fetch(session, ep,
                                      data={"step":i+1,"order_id":"1"},
                                      token=token)
            if s in (200, 201) and len(body) > 10:
                add(findings, f"Workflow Step Bypass — Step {i+1} of {len(workflow)}",
                    "HIGH",
                    f"Step {i+1} ('{step}') is directly accessible without "
                    f"completing prior steps. Business logic can be bypassed.",
                    ep, evidence=f"Direct access HTTP {s} ({len(body)}B)",
                    recommendation="Enforce workflow state server-side using sessions. "
                    "Verify all prerequisite steps are complete before allowing progression.")

# ── Check 9: Free Item Exploitation ──────────────────────
async def check_free_exploitation(session, origin, findings, token):
    free_payloads = [
        {"product_id":"1","price":0,"currency":"USD"},
        {"item":"premium","cost":0},
        {"plan":"premium","amount":0,"billing":"monthly"},
        {"subscription":"pro","price":0.0},
        {"product_id":"1","quantity":1,"coupon":"100OFF","final_price":0},
    ]

    for path in ORDER_ENDPOINTS + PAYMENT_ENDPOINTS:
        ep = f"{origin}{path}"
        for payload in free_payloads[:3]:
            s, body, _ = await fetch(session, ep, data=payload, token=token)
            if looks_successful(s, body) and s not in (404, 405, 0):
                add(findings, "Free Item Exploitation — Zero Cost Order", "CRITICAL",
                    f"Endpoint '{path}' accepted an order with zero cost. "
                    "Premium items may be obtainable for free.",
                    ep, evidence=f"Payload: {payload} | HTTP {s}",
                    recommendation="Server must calculate final price from product database. "
                    "Reject client-supplied price values entirely.")
                break

# ── Orchestrator ──────────────────────────────────────────
async def run_scanner(target_url, token=None):
    result = ScanResult(target=target_url)
    if not target_url.startswith(("http://","https://")):
        target_url = "https://" + target_url; result.target = target_url
    parsed = urlparse(target_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    connector = aiohttp.TCPConnector(ssl=False, limit=30)
    timeout   = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        start = time.perf_counter()
        findings = []
        checks = [
            ("Price/Amount Tampering",     check_price_tampering),
            ("Negative Quantity",          check_negative_quantity),
            ("Coupon/Discount Abuse",      check_coupon_abuse),
            ("Balance Manipulation",       check_balance_manipulation),
            ("Role/Privilege Escalation",  check_role_escalation),
            ("Race Conditions",            check_race_condition),
            ("Limit Bypass",               check_limit_bypass),
            ("Workflow Bypass",            check_workflow_bypass),
            ("Free Item Exploitation",     check_free_exploitation),
        ]
        print(f"  {DIM}Running {len(checks)} business logic checks concurrently...{RESET}")
        await asyncio.gather(
            *[fn(session, origin, findings, token) for _, fn in checks],
            return_exceptions=True,
        )
        result.duration = time.perf_counter() - start
        seen = set()
        for f in findings:
            k = (f.endpoint[:80], f.name[:40])
            if k not in seen: seen.add(k); result.findings.append(f)
    SEV = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
    result.findings.sort(key=lambda f: SEV.get(f.severity, 9))
    return result

def print_report(result):
    line = "═"*68
    print(f"\n{BOLD}{line}{RESET}")
    print(f"{BOLD}  BUSINESS LOGIC VULNERABILITY SCAN REPORT{RESET}")
    print(f"{line}")
    print(f"  Target   : {result.target}")
    print(f"  Duration : {result.duration:.2f}s")
    print(f"  Findings : {len(result.findings)}")
    print(f"{line}\n")
    if not result.findings:
        print(f"  {GREEN}✅  No business logic vulnerabilities detected.{RESET}\n")
        print(f"  {DIM}Note: Business logic flaws often require manual testing with a real account.{RESET}\n")
    else:
        from collections import Counter
        counts = Counter(f.severity for f in result.findings)
        print(f"  Severity Summary:")
        for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
            if counts[sev]:
                c   = SEV_COLOR[sev]
                bar = "█" * min(counts[sev] * 3, 36)
                print(f"    {c}{sev:<10}{RESET}  {bar}  {counts[sev]}")
        print()
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
    parser = argparse.ArgumentParser(description="Business Logic Scanner")
    parser.add_argument("url"); parser.add_argument("--token", default=None)
    args = parser.parse_args()
    print(f"\n  {BOLD}Business Logic Vulnerability Scanner{RESET}  |  Target: {args.url}")
    result = await run_scanner(args.url, args.token)
    print_report(result)

if __name__ == "__main__": asyncio.run(main())
