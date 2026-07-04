"""Surety: the authorization and liability rail for AI agents."""
from .crypto import Ed25519Signer, HmacSigner
from .certificate import issue, verify, tool_category
from .policy import evaluate, Decision, ALLOW, BLOCK, ESCROW
from .guard import Guard
from .store import Store
from .verifier import verify_action

__version__ = "0.2.0"
__all__ = ["Ed25519Signer", "HmacSigner", "issue", "verify", "tool_category",
           "evaluate", "Decision", "ALLOW", "BLOCK", "ESCROW",
           "Guard", "Store", "verify_action"]
