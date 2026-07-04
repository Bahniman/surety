"""Delegation certificates v2.

A certificate is a signed mandate from a human principal to an agent:

    scope:
      budget_total          total spend allowed under this certificate
      budget_categories     optional per-category caps, e.g. {"travel": 30000}
      allowed_tools         tool name -> spend category (the category map IS
                            the permission list; tools absent here are denied)
      allowed_domains       fnmatch patterns the agent may touch
      active_hours          [start_hour, end_hour) in which actions may run
      max_actions_per_hour  rate limit across all tools
      require_approval_over single-action amount that triggers human escrow
    valid_from / expires_at unix seconds
    principal_pub           embedded public key (ed25519) so ANY counterparty
                            can verify the mandate offline

Signing covers the canonical JSON of everything except the signature itself.
"""
import json
import time
import uuid

from .crypto import Ed25519Signer, HmacSigner

CERT_VERSION = 2


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def issue(signer, principal: str, agent_id: str, *,
          budget_total: float,
          allowed_tools: dict,
          allowed_domains: list,
          budget_categories: dict = None,
          active_hours: tuple = (0, 24),
          max_actions_per_hour: int = 60,
          require_approval_over: float = None,
          ttl_hours: float = 168,
          valid_from: float = None) -> dict:
    now = time.time()
    body = {
        "v": CERT_VERSION,
        "id": "cert_" + uuid.uuid4().hex[:12],
        "principal": principal,
        "agent": agent_id,
        "scheme": signer.scheme,
        "principal_pub": signer.public_hex,
        "scope": {
            "budget_total": float(budget_total),
            "budget_categories": dict(sorted((budget_categories or {}).items())),
            "allowed_tools": dict(sorted(allowed_tools.items())),
            "allowed_domains": sorted(allowed_domains),
            "active_hours": list(active_hours),
            "max_actions_per_hour": int(max_actions_per_hour),
            "require_approval_over": require_approval_over,
        },
        "valid_from": valid_from if valid_from is not None else now,
        "expires_at": now + ttl_hours * 3600,
    }
    cert = dict(body)
    cert["sig"] = signer.sign(canonical(body))
    return cert


def signing_body(cert: dict) -> dict:
    return {k: v for k, v in cert.items() if k != "sig"}


def verify(cert: dict, hmac_secret: str = None) -> bool:
    """Verify authenticity. Ed25519 certs verify against the embedded public
    key (no secret needed - this is what lets merchants check offline).
    HMAC certs need the shared secret."""
    try:
        msg = canonical(signing_body(cert))
        if cert.get("scheme") == "ed25519":
            return Ed25519Signer.verify(msg, cert["sig"], cert["principal_pub"])
        if cert.get("scheme") == "hmac-sha256":
            if hmac_secret is None:
                return False
            return HmacSigner(hmac_secret).verify_with_secret(msg, cert["sig"])
        return False
    except (KeyError, TypeError):
        return False


def tool_category(cert: dict, tool: str):
    """The spend category a tool bills against, or None if not permitted."""
    return cert["scope"]["allowed_tools"].get(tool)
