"""The policy engine: one function that answers "may this action run?"

Checks run in a fixed, documented order; the first failure wins. Every
decision carries the full evidence list, because an enforcement layer that
can't explain itself won't survive its first compliance review.

Order:
  1. certificate authenticity (signature)
  2. revocation
  3. validity window (valid_from / expires_at)
  4. active hours
  5. tool permitted (and mapped to a spend category)
  6. domain allow-list (fnmatch)
  7. rate limit (actions in the trailing hour)
  8. category budget
  9. total budget
 10. approval threshold  ->  ESCROW instead of ALLOW
"""
import time
from fnmatch import fnmatch

from . import certificate as cert_mod

ALLOW, BLOCK, ESCROW = "ALLOW", "BLOCK", "ESCROW"


class Decision:
    def __init__(self, verdict, reason, evidence=None, category=None):
        self.verdict = verdict
        self.reason = reason
        self.evidence = evidence or []
        self.category = category
        self.escrow_id = None

    def __repr__(self):
        return f"<{self.verdict}: {self.reason}>"


def evaluate(cert: dict, store, *, tool: str, domain: str = None,
             amount: float = 0.0, now: float = None,
             hmac_secret: str = None) -> Decision:
    now = now if now is not None else time.time()
    scope = cert["scope"]
    ev = []

    # 1. authenticity
    if not cert_mod.verify(cert, hmac_secret=hmac_secret):
        return Decision(BLOCK, "certificate signature invalid", ev)
    ev.append("signature verified (" + cert["scheme"] + ")")

    # 2. revocation
    if store.is_revoked(cert["id"]):
        return Decision(BLOCK, "certificate revoked by principal", ev)
    ev.append("not revoked")

    # 3. validity window
    if now < cert["valid_from"]:
        return Decision(BLOCK, "certificate not yet valid", ev)
    if now > cert["expires_at"]:
        return Decision(BLOCK, "certificate expired", ev)
    ev.append("within validity window")

    # 4. active hours
    h0, h1 = scope["active_hours"]
    hour = time.localtime(now).tm_hour
    inside = h0 <= hour < h1 if h0 <= h1 else (hour >= h0 or hour < h1)
    if not inside:
        return Decision(BLOCK,
                        f"outside active hours {h0:02d}:00-{h1:02d}:00 (now {hour:02d}:xx)", ev)
    ev.append(f"inside active hours {h0:02d}-{h1:02d}")

    # 5. tool -> category
    category = cert_mod.tool_category(cert, tool)
    if category is None:
        return Decision(BLOCK, f"tool '{tool}' is not in the mandate", ev)
    ev.append(f"tool '{tool}' maps to category '{category}'")

    # 6. domain
    if domain:
        if not any(fnmatch(domain, pat) for pat in scope["allowed_domains"]):
            return Decision(BLOCK, f"domain '{domain}' not allow-listed", ev)
        ev.append(f"domain '{domain}' allow-listed")

    # 7. rate limit
    recent = store.actions_since(cert["id"], now - 3600)
    limit = scope["max_actions_per_hour"]
    if recent >= limit:
        return Decision(BLOCK,
                        f"rate limit: {recent} actions in the last hour (max {limit})", ev)
    ev.append(f"rate ok ({recent}/{limit} in trailing hour)")

    # 8. category budget
    cat_cap = scope["budget_categories"].get(category)
    if amount and cat_cap is not None:
        cat_spent = store.spent_category(cert["id"], category)
        if cat_spent + amount > cat_cap:
            return Decision(
                BLOCK,
                f"category '{category}' budget: spent {cat_spent:.0f} + {amount:.0f} "
                f"> cap {cat_cap:.0f}", ev, category)
        ev.append(f"category budget ok ({cat_spent:.0f}+{amount:.0f}<={cat_cap:.0f})")

    # 9. total budget
    if amount:
        total_spent = store.spent_total(cert["id"])
        if total_spent + amount > scope["budget_total"]:
            return Decision(
                BLOCK,
                f"total budget: spent {total_spent:.0f} + {amount:.0f} "
                f"> cap {scope['budget_total']:.0f}", ev, category)
        ev.append(f"total budget ok ({total_spent:.0f}+{amount:.0f}"
                  f"<={scope['budget_total']:.0f})")

    # 10. approval threshold
    thr = scope.get("require_approval_over")
    if amount and thr is not None and amount > thr:
        return Decision(ESCROW,
                        f"amount {amount:.0f} exceeds approval threshold {thr:.0f}",
                        ev, category)

    return Decision(ALLOW, "in scope", ev, category)
