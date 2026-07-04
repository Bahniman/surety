"""Signing backends for Surety certificates and receipts.

Two backends, one interface:

- Ed25519Signer: real public-key signatures. Anyone holding the public key
  can verify a certificate offline; the secret never leaves the principal.
  Implemented in pure Python from RFC 8032 (no dependencies). This is the
  reference construction, verified against the RFC test vectors in
  tests/test_surety.py. It is deliberately unoptimized (~100ms per
  operation) - production swaps in libsodium/`cryptography` behind the
  same interface.

- HmacSigner: shared-secret signatures for closed-loop deployments where
  issuer and verifier are the same party.
"""
import hashlib
import hmac as _hmac
import os

# --------------------------------------------------------------------------
# Ed25519, pure Python (RFC 8032). Reference construction.
# --------------------------------------------------------------------------
_p = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493


def _H(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _inv(x: int) -> int:
    return pow(x, _p - 2, _p)


_d = -121665 * _inv(121666) % _p
_I = pow(2, (_p - 1) // 4, _p)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = pow(xx, (_p + 3) // 8, _p)
    if (x * x - xx) % _p != 0:
        x = x * _I % _p
    if x % 2 != 0:
        x = _p - x
    return x


_By = 4 * _inv(5) % _p
_Bx = _xrecover(_By)
_B = (_Bx, _By)


def _edwards_add(P, Q):
    x1, y1 = P
    x2, y2 = Q
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _d * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _d * x1 * x2 * y1 * y2)
    return (x3 % _p, y3 % _p)


def _scalarmult(P, e: int):
    Q = (0, 1)
    while e:
        if e & 1:
            Q = _edwards_add(Q, P)
        P = _edwards_add(P, P)
        e >>= 1
    return Q


def _encodepoint(P) -> bytes:
    x, y = P
    n = y | ((x & 1) << 255)
    return n.to_bytes(32, "little")


def _bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def _isoncurve(P) -> bool:
    x, y = P
    return (-x * x + y * y - 1 - _d * x * x * y * y) % _p == 0


def _decodepoint(s: bytes):
    n = int.from_bytes(s, "little")
    y = n & ((1 << 255) - 1)
    x = _xrecover(y)
    if x & 1 != (n >> 255) & 1:
        x = _p - x
    P = (x, y)
    if not _isoncurve(P):
        raise ValueError("point not on curve")
    return P


def _secret_scalar(seed: bytes) -> int:
    h = _H(seed)
    a = 2**254 + sum(2**i * _bit(h, i) for i in range(3, 254))
    return a


def ed25519_publickey(seed: bytes) -> bytes:
    """Derive the 32-byte public key from a 32-byte seed."""
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    return _encodepoint(_scalarmult(_B, _secret_scalar(seed)))


def _Hint(m: bytes) -> int:
    return int.from_bytes(_H(m), "little")


def ed25519_sign(msg: bytes, seed: bytes, pub: bytes) -> bytes:
    h = _H(seed)
    a = _secret_scalar(seed)
    r = _Hint(h[32:64] + msg)
    R = _scalarmult(_B, r)
    Renc = _encodepoint(R)
    S = (r + _Hint(Renc + pub + msg) * a) % _L
    return Renc + S.to_bytes(32, "little")


def ed25519_verify(sig: bytes, msg: bytes, pub: bytes) -> bool:
    if len(sig) != 64 or len(pub) != 32:
        return False
    try:
        R = _decodepoint(sig[:32])
        A = _decodepoint(pub)
    except Exception:
        return False
    S = int.from_bytes(sig[32:], "little")
    if S >= _L:
        return False
    h = _Hint(sig[:32] + pub + msg)
    return _scalarmult(_B, S) == _edwards_add(R, _scalarmult(A, h))


# --------------------------------------------------------------------------
# The signer interface Surety uses
# --------------------------------------------------------------------------
class Ed25519Signer:
    """Public-key signer. verify() needs only the public key."""

    scheme = "ed25519"

    def __init__(self, seed: bytes = None):
        self.seed = seed or os.urandom(32)
        self.public_key = ed25519_publickey(self.seed)

    @property
    def public_hex(self) -> str:
        return self.public_key.hex()

    def sign(self, msg: bytes) -> str:
        return ed25519_sign(msg, self.seed, self.public_key).hex()

    @staticmethod
    def verify(msg: bytes, sig_hex: str, public_hex: str) -> bool:
        try:
            return ed25519_verify(bytes.fromhex(sig_hex), msg,
                                  bytes.fromhex(public_hex))
        except ValueError:
            return False


class HmacSigner:
    """Shared-secret signer for closed-loop deployments."""

    scheme = "hmac-sha256"

    def __init__(self, secret: str):
        self.secret = secret
        self.public_hex = hashlib.sha256(("pub:" + secret).encode()).hexdigest()

    def sign(self, msg: bytes) -> str:
        return _hmac.new(self.secret.encode(), msg, hashlib.sha256).hexdigest()

    def verify_with_secret(self, msg: bytes, sig_hex: str) -> bool:
        return _hmac.compare_digest(self.sign(msg), sig_hex)
