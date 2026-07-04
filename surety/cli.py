"""Surety command line.

    python -m surety keygen --out principal.key
    python -m surety issue --key principal.key --agent procure-01 \
        --principal cfo@corp.com --budget 250000 \
        --tool saas_renewal=software --tool book_travel=travel \
        --category travel=60000 --domain "*.makemytrip.com" \
        --threshold 50000 --out mandate.json
    python -m surety inspect mandate.json
    python -m surety verify mandate.json --tool book_travel \
        --domain www.makemytrip.com --amount 24650
    python -m surety revoke mandate.json --db surety.db
    python -m surety log --db surety.db
    python -m surety demo
"""
import argparse
import json
import sys

from .crypto import Ed25519Signer
from . import certificate as cert_mod
from .verifier import verify_action
from .store import Store


def _load_cert(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="surety",
                                 description="Delegation certificates for AI agents")
    sub = ap.add_subparsers(dest="cmd", required=True)

    k = sub.add_parser("keygen", help="generate a principal keypair")
    k.add_argument("--out", default="principal.key")

    i = sub.add_parser("issue", help="issue a signed mandate")
    i.add_argument("--key", required=True)
    i.add_argument("--principal", required=True)
    i.add_argument("--agent", required=True)
    i.add_argument("--budget", type=float, required=True)
    i.add_argument("--tool", action="append", default=[],
                   metavar="NAME=CATEGORY", help="repeatable")
    i.add_argument("--category", action="append", default=[],
                   metavar="CATEGORY=CAP", help="repeatable")
    i.add_argument("--domain", action="append", default=[], help="repeatable")
    i.add_argument("--threshold", type=float, default=None)
    i.add_argument("--hours", default="0-24", help="active hours, e.g. 9-19")
    i.add_argument("--rate", type=int, default=60, help="max actions/hour")
    i.add_argument("--ttl", type=float, default=168, help="hours until expiry")
    i.add_argument("--out", default="mandate.json")

    n = sub.add_parser("inspect", help="human-readable view of a mandate")
    n.add_argument("mandate")

    v = sub.add_parser("verify", help="merchant-side offline check")
    v.add_argument("mandate")
    v.add_argument("--tool", required=True)
    v.add_argument("--domain")
    v.add_argument("--amount", type=float, default=0)

    r = sub.add_parser("revoke", help="revoke a mandate in a store")
    r.add_argument("mandate")
    r.add_argument("--db", default="surety.db")

    l = sub.add_parser("log", help="print and verify the audit chain")
    l.add_argument("--db", default="surety.db")

    sub.add_parser("demo", help="run the guided demo")

    a = ap.parse_args(argv)

    if a.cmd == "keygen":
        s = Ed25519Signer()
        with open(a.out, "w", encoding="utf-8") as f:
            json.dump({"seed": s.seed.hex(), "public": s.public_hex}, f)
        print(f"keypair written to {a.out}")
        print(f"public key: {s.public_hex}")

    elif a.cmd == "issue":
        with open(a.key, encoding="utf-8") as f:
            kd = json.load(f)
        signer = Ed25519Signer(bytes.fromhex(kd["seed"]))
        tools = dict(t.split("=", 1) for t in a.tool)
        cats = {c.split("=")[0]: float(c.split("=")[1]) for c in a.category}
        h0, h1 = (int(x) for x in a.hours.split("-"))
        cert = cert_mod.issue(
            signer, a.principal, a.agent, budget_total=a.budget,
            allowed_tools=tools, allowed_domains=a.domain,
            budget_categories=cats, active_hours=(h0, h1),
            max_actions_per_hour=a.rate, require_approval_over=a.threshold,
            ttl_hours=a.ttl)
        with open(a.out, "w", encoding="utf-8") as f:
            json.dump(cert, f, indent=2)
        print(f"mandate {cert['id']} written to {a.out}")

    elif a.cmd == "inspect":
        c = _load_cert(a.mandate)
        s = c["scope"]
        print(f"mandate    {c['id']}  (v{c['v']}, {c['scheme']})")
        print(f"principal  {c['principal']}")
        print(f"agent      {c['agent']}")
        print(f"budget     {s['budget_total']:.0f} total"
              + (f", categories {s['budget_categories']}" if s['budget_categories'] else ""))
        print(f"tools      {s['allowed_tools']}")
        print(f"domains    {s['allowed_domains']}")
        print(f"hours      {s['active_hours'][0]:02d}:00-{s['active_hours'][1]:02d}:00"
              f"  rate {s['max_actions_per_hour']}/h"
              f"  approval over {s['require_approval_over']}")
        print(f"authentic  {cert_mod.verify(c)}")

    elif a.cmd == "verify":
        c = _load_cert(a.mandate)
        res = verify_action(c, tool=a.tool, domain=a.domain, amount=a.amount)
        for chk in res["checks"]:
            print(("  [ok] " if chk["passed"] else "  [X ] ") + chk["check"])
        print("authentic:", res["authentic"], "| in scope:", res["in_scope"])
        sys.exit(0 if (res["authentic"] and res["in_scope"]) else 1)

    elif a.cmd == "revoke":
        c = _load_cert(a.mandate)
        st = Store(a.db)
        st.put_cert(c)
        st.revoke(c["id"])
        st.append_audit({"event": "certificate_revoked", "cert": c["id"]})
        print(f"{c['id']} revoked in {a.db}")

    elif a.cmd == "log":
        st = Store(a.db)
        for e in st.audit_entries():
            b = e["body"]
            print(f"#{e['seq']:>3}  {b.get('event','?'):<24} "
                  f"{b.get('tool','')} {b.get('verdict','')} {b.get('reason','')}")
        ok, bad = st.verify_chain()
        print("chain intact:", ok, ("" if ok else f"(breaks at #{bad})"))

    elif a.cmd == "demo":
        from . import demo_scenario
        demo_scenario.run()


if __name__ == "__main__":
    main()
