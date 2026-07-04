"""The enforcement middleware. Sits between an agent and its tools; every
tool call is checked against the delegation certificate before it executes."""
import time
import uuid
from fnmatch import fnmatch

from .certificate import verify as verify_cert
from .audit import AuditLog

ALLOW, BLOCK, ESCROW = "ALLOW", "BLOCK", "ESCROW"


class Decision:
    def __init__(self, verdict: str, reason: str, escrow_id: str = None):
        self.verdict = verdict
        self.reason = reason
        self.escrow_id = escrow_id

    def __repr__(self):
        return f"<{self.verdict}: {self.reason}>"


class Guard:
    """Wraps an agent's tool access with certificate enforcement.

    guard = Guard(cert, principal_secret)
    decision = guard.request(tool="book_flight", domain="makemytrip.com",
                             amount=3200, detail="BLR-DEL 14 Jul")
    """

    def __init__(self, cert: dict, secret: str, log: AuditLog = None):
        self._secret = secret
        self.cert = cert
        self.log = log or AuditLog()
        self.spent = 0.0
        self.pending = {}
        if not verify_cert(cert, secret):
            raise ValueError("certificate signature invalid: refusing to guard")
        self.log.append({"event": "guard_start", "cert": cert["id"],
                         "agent": cert["agent"], "principal": cert["principal"]})

    # ---------------------------------------------------------------- checks
    def _check(self, tool, domain, amount):
        scope = self.cert["scope"]
        if self.cert.get("revoked"):
            return BLOCK, "certificate revoked"
        if time.time() > self.cert["expires_at"]:
            return BLOCK, "certificate expired"
        if tool not in scope["allowed_tools"]:
            return BLOCK, f"tool '{tool}' not in allowed_tools"
        if domain and not any(fnmatch(domain, pat) for pat in scope["allowed_domains"]):
            return BLOCK, f"domain '{domain}' not in allowed_domains"
        if amount and self.spent + amount > scope["max_spend"]:
            return BLOCK, (f"would exceed budget: spent {self.spent:.0f} + "
                           f"{amount:.0f} > cap {scope['max_spend']:.0f}")
        threshold = scope.get("require_approval_over")
        if amount and threshold is not None and amount > threshold:
            return ESCROW, f"amount {amount:.0f} exceeds approval threshold {threshold:.0f}"
        return ALLOW, "in scope"

    # ---------------------------------------------------------------- public
    def request(self, tool: str, *, domain: str = None, amount: float = 0,
                detail: str = "") -> Decision:
        verdict, reason = self._check(tool, domain, amount)
        record = {"event": "tool_request", "tool": tool, "domain": domain,
                  "amount": amount, "detail": detail, "verdict": verdict,
                  "reason": reason, "cert": self.cert["id"]}
        if verdict == ALLOW:
            self.spent += amount
            record["spent_total"] = self.spent
            self.log.append(record)
            return Decision(ALLOW, reason)
        if verdict == ESCROW:
            eid = "esc_" + uuid.uuid4().hex[:8]
            self.pending[eid] = {"tool": tool, "domain": domain,
                                 "amount": amount, "detail": detail}
            record["escrow_id"] = eid
            self.log.append(record)
            return Decision(ESCROW, reason, escrow_id=eid)
        self.log.append(record)
        return Decision(BLOCK, reason)

    def approve(self, escrow_id: str, approver: str) -> Decision:
        item = self.pending.pop(escrow_id, None)
        if item is None:
            return Decision(BLOCK, f"no pending escrow {escrow_id}")
        verdict, reason = self._check(item["tool"], item["domain"], item["amount"])
        if verdict == BLOCK:  # conditions may have changed since escrowed
            self.log.append({"event": "escrow_denied_on_recheck",
                             "escrow_id": escrow_id, "reason": reason})
            return Decision(BLOCK, reason)
        self.spent += item["amount"]
        self.log.append({"event": "escrow_approved", "escrow_id": escrow_id,
                         "approver": approver, "amount": item["amount"],
                         "spent_total": self.spent})
        return Decision(ALLOW, f"approved by {approver}")

    def deny(self, escrow_id: str, approver: str, why: str = "") -> Decision:
        self.pending.pop(escrow_id, None)
        self.log.append({"event": "escrow_denied", "escrow_id": escrow_id,
                         "approver": approver, "reason": why})
        return Decision(BLOCK, f"denied by {approver}: {why}")

    @property
    def remaining(self) -> float:
        return self.cert["scope"]["max_spend"] - self.spent
