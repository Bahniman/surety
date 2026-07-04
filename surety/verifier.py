"""Merchant-side verification: check a mandate and an action receipt offline.

A merchant receiving an agent's order wants two answers without calling
anyone: (1) is this mandate authentic and in force, (2) does this specific
action fall inside it. With Ed25519 certificates both answers come from the
embedded public key - no API, no shared secret, no network.

    result = verify_action(cert, tool="book_flight",
                           domain="www.airline.com", amount=2100)
    result -> {"authentic": True, "in_scope": True, "checks": [...]}

The merchant still cannot see the agent's spend history (that lives with
the guard), so `in_scope` here means "within the mandate's static limits".
Production adds a signed spend-state attestation from the guard for the
dynamic part; the shape of that receipt is documented in docs/ARCHITECTURE.md.
"""
import time
from fnmatch import fnmatch

from . import certificate as cert_mod


def verify_action(cert: dict, *, tool: str, domain: str = None,
                  amount: float = 0.0, now: float = None) -> dict:
    now = now if now is not None else time.time()
    checks = []
    ok = True

    authentic = cert_mod.verify(cert)
    checks.append(("signature", authentic))
    ok &= authentic

    if authentic:
        in_window = cert["valid_from"] <= now <= cert["expires_at"]
        checks.append(("validity window", in_window)); ok &= in_window

        cat = cert_mod.tool_category(cert, tool)
        checks.append((f"tool '{tool}' permitted", cat is not None))
        ok &= cat is not None

        if domain:
            dom_ok = any(fnmatch(domain, p) for p in cert["scope"]["allowed_domains"])
            checks.append((f"domain '{domain}' permitted", dom_ok)); ok &= dom_ok

        within_total = amount <= cert["scope"]["budget_total"]
        checks.append(("amount within total budget ceiling", within_total))
        ok &= within_total

        if cat is not None:
            cap = cert["scope"]["budget_categories"].get(cat)
            if cap is not None:
                within_cat = amount <= cap
                checks.append((f"amount within '{cat}' category ceiling", within_cat))
                ok &= within_cat

    return {"authentic": authentic, "in_scope": bool(ok),
            "checks": [{"check": c, "passed": bool(p)} for c, p in checks]}
