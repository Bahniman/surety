"""SQLite persistence: certificate registry, spend state, audit log, escrow.

Everything Surety needs to survive a process restart lives here. The audit
table is append-only and hash-chained; verify_chain() recomputes every link.
"""
import json
import sqlite3
import time

GENESIS = "0" * 64

_SCHEMA = """
CREATE TABLE IF NOT EXISTS certs (
  id TEXT PRIMARY KEY, agent TEXT, principal TEXT,
  body TEXT NOT NULL, revoked INTEGER DEFAULT 0, created REAL
);
CREATE TABLE IF NOT EXISTS spend (
  cert_id TEXT, category TEXT, amount REAL, ts REAL
);
CREATE TABLE IF NOT EXISTS audit (
  seq INTEGER PRIMARY KEY, body TEXT NOT NULL,
  prev TEXT NOT NULL, hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS escrow (
  id TEXT PRIMARY KEY, cert_id TEXT, body TEXT NOT NULL,
  status TEXT DEFAULT 'pending', created REAL, expires REAL
);
"""


class Store:
    def __init__(self, path: str = ":memory:"):
        self.db = sqlite3.connect(path)
        self.db.executescript(_SCHEMA)
        self.db.commit()

    # ------------------------------------------------------------- certs
    def put_cert(self, cert: dict):
        self.db.execute(
            "INSERT OR REPLACE INTO certs (id, agent, principal, body, revoked, created)"
            " VALUES (?,?,?,?,COALESCE((SELECT revoked FROM certs WHERE id=?),0),?)",
            (cert["id"], cert["agent"], cert["principal"], json.dumps(cert),
             cert["id"], time.time()))
        self.db.commit()

    def get_cert(self, cert_id: str):
        row = self.db.execute("SELECT body FROM certs WHERE id=?", (cert_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def revoke(self, cert_id: str):
        self.db.execute("UPDATE certs SET revoked=1 WHERE id=?", (cert_id,))
        self.db.commit()

    def is_revoked(self, cert_id: str) -> bool:
        row = self.db.execute("SELECT revoked FROM certs WHERE id=?", (cert_id,)).fetchone()
        return bool(row and row[0])

    # ------------------------------------------------------------- spend
    def add_spend(self, cert_id: str, category: str, amount: float):
        self.db.execute("INSERT INTO spend VALUES (?,?,?,?)",
                        (cert_id, category, amount, time.time()))
        self.db.commit()

    def spent_total(self, cert_id: str) -> float:
        row = self.db.execute(
            "SELECT COALESCE(SUM(amount),0) FROM spend WHERE cert_id=?", (cert_id,)).fetchone()
        return row[0]

    def spent_category(self, cert_id: str, category: str) -> float:
        row = self.db.execute(
            "SELECT COALESCE(SUM(amount),0) FROM spend WHERE cert_id=? AND category=?",
            (cert_id, category)).fetchone()
        return row[0]

    def actions_since(self, cert_id: str, since_ts: float) -> int:
        row = self.db.execute(
            "SELECT COUNT(*) FROM spend WHERE cert_id=? AND ts>=?",
            (cert_id, since_ts)).fetchone()
        return row[0]

    def record_action_tick(self, cert_id: str):
        """Zero-amount actions still count against the rate limit."""
        self.add_spend(cert_id, "__tick__", 0.0)

    # ------------------------------------------------------------- audit
    def _sha(self, s: str) -> str:
        import hashlib
        return hashlib.sha256(s.encode()).hexdigest()

    def append_audit(self, event: dict) -> dict:
        row = self.db.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        prev = row[0] if row else GENESIS
        seq_row = self.db.execute("SELECT COALESCE(MAX(seq),-1)+1 FROM audit").fetchone()
        seq = seq_row[0]
        entry = dict(event)
        entry["seq"] = seq
        entry["ts"] = time.time()
        body = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        h = self._sha(body + prev)
        self.db.execute("INSERT INTO audit (seq, body, prev, hash) VALUES (?,?,?,?)",
                        (seq, body, prev, h))
        self.db.commit()
        entry["hash"] = h
        return entry

    def audit_entries(self):
        return [
            {"seq": seq, "body": json.loads(body), "prev": prev, "hash": h}
            for seq, body, prev, h in
            self.db.execute("SELECT seq, body, prev, hash FROM audit ORDER BY seq")
        ]

    def verify_chain(self):
        prev = GENESIS
        for row in self.db.execute("SELECT seq, body, prev, hash FROM audit ORDER BY seq"):
            seq, body, stored_prev, stored_hash = row
            if stored_prev != prev:
                return False, seq
            if self._sha(body + stored_prev) != stored_hash:
                return False, seq
            prev = stored_hash
        return True, None

    # ------------------------------------------------------------ escrow
    def put_escrow(self, eid: str, cert_id: str, item: dict, ttl_s: float):
        now = time.time()
        self.db.execute("INSERT INTO escrow VALUES (?,?,?,?,?,?)",
                        (eid, cert_id, json.dumps(item), "pending", now, now + ttl_s))
        self.db.commit()

    def get_escrow(self, eid: str):
        row = self.db.execute(
            "SELECT body, status, expires FROM escrow WHERE id=?", (eid,)).fetchone()
        if not row:
            return None
        return {"item": json.loads(row[0]), "status": row[1], "expires": row[2]}

    def set_escrow_status(self, eid: str, status: str):
        self.db.execute("UPDATE escrow SET status=? WHERE id=?", (status, eid))
        self.db.commit()

    def pending_escrows(self, cert_id: str = None):
        q = "SELECT id, body, expires FROM escrow WHERE status='pending'"
        args = ()
        if cert_id:
            q += " AND cert_id=?"
            args = (cert_id,)
        return [{"id": i, "item": json.loads(b), "expires": e}
                for i, b, e in self.db.execute(q, args)]
