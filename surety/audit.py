"""Tamper-evident audit log: every entry carries the hash of the previous
entry, so any edit or deletion breaks the chain and is detectable."""
import hashlib
import json
import time

GENESIS = "0" * 64


def _canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


class AuditLog:
    def __init__(self):
        self.entries = []

    def append(self, event: dict) -> dict:
        prev = self.entries[-1]["hash"] if self.entries else GENESIS
        entry = dict(event)
        entry["seq"] = len(self.entries)
        entry["ts"] = time.time()
        entry["prev"] = prev
        entry["hash"] = hashlib.sha256(
            _canonical({k: v for k, v in entry.items() if k != "hash"}).encode()
        ).hexdigest()
        self.entries.append(entry)
        return entry

    def verify_chain(self) -> tuple:
        """Returns (ok, first_bad_seq). Recomputes every hash and link."""
        prev = GENESIS
        for e in self.entries:
            body = {k: v for k, v in e.items() if k != "hash"}
            if e.get("prev") != prev:
                return False, e.get("seq")
            if hashlib.sha256(_canonical(body).encode()).hexdigest() != e.get("hash"):
                return False, e.get("seq")
            prev = e["hash"]
        return True, None

    def save(self, path: str):
        with open(path, "w", encoding="utf-8") as f:
            for e in self.entries:
                f.write(json.dumps(e) + "\n")
