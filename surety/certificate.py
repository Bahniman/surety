"""Delegation certificates: a scoped, revocable, verifiable grant of authority
from a human principal to an AI agent.

Prototype signing uses HMAC-SHA256 with the principal's secret. Production
design (see docs/ARCHITECTURE.md) replaces this with Ed25519 keypairs so any
third party can verify without the secret.
"""
import hashlib
import hmac
import json
import time
import uuid


def _canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _sign(body: dict, secret: str) -> str:
    return hmac.new(secret.encode(), _canonical(body).encode(), hashlib.sha256).hexdigest()


def issue(principal: str, secret: str, agent_id: str, *,
          max_spend: float,
          currency: str = "INR",
          allowed_tools: list,
          allowed_domains: list,
          ttl_hours: int = 168,
          require_approval_over: float = None) -> dict:
    """Issue a signed delegation certificate.

    max_spend             total budget the agent may spend under this cert
    allowed_tools         tool names the agent may invoke (exact match)
    allowed_domains       domains the agent may touch (fnmatch patterns ok)
    ttl_hours             certificate lifetime
    require_approval_over single-action amount above which the action is
                          escrowed for explicit human approval
    """
    now = int(time.time())
    body = {
        "id": "cert_" + uuid.uuid4().hex[:12],
        "v": 1,
        "principal": principal,
        "agent": agent_id,
        "scope": {
            "max_spend": max_spend,
            "currency": currency,
            "allowed_tools": sorted(allowed_tools),
            "allowed_domains": sorted(allowed_domains),
            "require_approval_over": require_approval_over,
        },
        "issued_at": now,
        "expires_at": now + ttl_hours * 3600,
        "revoked": False,
    }
    cert = dict(body)
    cert["sig"] = _sign(body, secret)
    return cert


def verify(cert: dict, secret: str) -> bool:
    """True if the certificate is authentic and untampered."""
    body = {k: v for k, v in cert.items() if k != "sig"}
    return hmac.compare_digest(_sign(body, secret), cert.get("sig", ""))


def revoke(cert: dict, secret: str) -> dict:
    """Return a revoked (and re-signed) copy of the certificate."""
    body = {k: v for k, v in cert.items() if k != "sig"}
    body["revoked"] = True
    out = dict(body)
    out["sig"] = _sign(body, secret)
    return out
