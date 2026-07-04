"""The Guard: policy + persistence + escrow + audit, in front of every tool.

    store = Store("surety.db")            # or Store() for in-memory
    guard = Guard(cert, store)
    d = guard.request(tool="book_flight", domain="x.com", amount=2100)
    if d.verdict == "ALLOW": ...          # execute the real tool call

Escrows expire (default 24h): an approval that never comes is a denial,
not a landmine. Approvals re-run the full policy - conditions may have
changed since the action was parked.
"""
import time
import uuid

from . import policy
from .policy import ALLOW, BLOCK, ESCROW, Decision
from .store import Store

DEFAULT_ESCROW_TTL_S = 24 * 3600


class Guard:
    def __init__(self, cert: dict, store: Store = None, *,
                 hmac_secret: str = None, escrow_ttl_s: float = DEFAULT_ESCROW_TTL_S):
        self.cert = cert
        self.store = store or Store()
        self.hmac_secret = hmac_secret
        self.escrow_ttl_s = escrow_ttl_s
        self.store.put_cert(cert)
        self.store.append_audit({"event": "guard_start", "cert": cert["id"],
                                 "agent": cert["agent"], "principal": cert["principal"]})

    # ----------------------------------------------------------------- API
    def request(self, tool: str, *, domain: str = None, amount: float = 0.0,
                detail: str = "", now: float = None) -> Decision:
        d = policy.evaluate(self.cert, self.store, tool=tool, domain=domain,
                            amount=amount, now=now, hmac_secret=self.hmac_secret)
        record = {"event": "tool_request", "cert": self.cert["id"], "tool": tool,
                  "domain": domain, "amount": amount, "detail": detail,
                  "verdict": d.verdict, "reason": d.reason, "evidence": d.evidence}
        if d.verdict == ALLOW:
            self.store.add_spend(self.cert["id"], d.category or "__none__", amount)
            record["spent_total"] = self.store.spent_total(self.cert["id"])
        elif d.verdict == ESCROW:
            eid = "esc_" + uuid.uuid4().hex[:8]
            self.store.put_escrow(eid, self.cert["id"],
                                  {"tool": tool, "domain": domain,
                                   "amount": amount, "detail": detail},
                                  self.escrow_ttl_s)
            d.escrow_id = eid
            record["escrow_id"] = eid
        self.store.append_audit(record)
        return d

    def approve(self, escrow_id: str, approver: str, now: float = None) -> Decision:
        now = now if now is not None else time.time()
        esc = self.store.get_escrow(escrow_id)
        if esc is None or esc["status"] != "pending":
            return Decision(BLOCK, f"no pending escrow '{escrow_id}'")
        if now > esc["expires"]:
            self.store.set_escrow_status(escrow_id, "expired")
            self.store.append_audit({"event": "escrow_expired", "escrow_id": escrow_id})
            return Decision(BLOCK, "escrow expired before approval")
        item = esc["item"]
        # re-run policy minus the threshold rule: simulate by evaluating with
        # amount at threshold (budget/category/rate checks still apply fully)
        d = policy.evaluate(self.cert, self.store, tool=item["tool"],
                            domain=item["domain"], amount=item["amount"], now=now,
                            hmac_secret=self.hmac_secret)
        if d.verdict == BLOCK:
            self.store.set_escrow_status(escrow_id, "denied_on_recheck")
            self.store.append_audit({"event": "escrow_denied_on_recheck",
                                     "escrow_id": escrow_id, "reason": d.reason})
            return Decision(BLOCK, "conditions changed since escrow: " + d.reason)
        self.store.add_spend(self.cert["id"], d.category or "__none__", item["amount"])
        self.store.set_escrow_status(escrow_id, "approved")
        self.store.append_audit({"event": "escrow_approved", "escrow_id": escrow_id,
                                 "approver": approver, "amount": item["amount"],
                                 "spent_total": self.store.spent_total(self.cert["id"])})
        return Decision(ALLOW, f"approved by {approver}")

    def deny(self, escrow_id: str, approver: str, why: str = "") -> Decision:
        esc = self.store.get_escrow(escrow_id)
        if esc is None or esc["status"] != "pending":
            return Decision(BLOCK, f"no pending escrow '{escrow_id}'")
        self.store.set_escrow_status(escrow_id, "denied")
        self.store.append_audit({"event": "escrow_denied", "escrow_id": escrow_id,
                                 "approver": approver, "reason": why})
        return Decision(BLOCK, f"denied by {approver}: {why}")

    def revoke(self):
        """Principal pulls the mandate. Everything stops, provably."""
        self.store.revoke(self.cert["id"])
        self.store.append_audit({"event": "certificate_revoked", "cert": self.cert["id"]})

    # ------------------------------------------------------------- helpers
    @property
    def spent(self) -> float:
        return self.store.spent_total(self.cert["id"])

    @property
    def remaining(self) -> float:
        return self.cert["scope"]["budget_total"] - self.spent

    def category_state(self) -> dict:
        out = {}
        for cat, cap in self.cert["scope"]["budget_categories"].items():
            out[cat] = {"cap": cap,
                        "spent": self.store.spent_category(self.cert["id"], cat)}
        return out
