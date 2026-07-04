"""The guided demo scenario, shared by `python demo.py` and `python -m surety demo`.

A month of a procurement agent at a mid-size company, guarded by a signed
mandate with category budgets, business-hours enforcement, a rate limit,
an approval threshold - and a revocation finale.
"""
from .crypto import Ed25519Signer
from . import certificate as cert_mod
from .guard import Guard
from .store import Store

W = 76


def banner(t):
    print("\n" + "=" * W + "\n" + t + "\n" + "=" * W)


def show(step, d):
    print(f"  {step:<54} -> [{d.verdict}] {d.reason}")


def run():
    banner("SURETY v0.2: a signed mandate, enforced on every call")

    cfo = Ed25519Signer()
    cert = cert_mod.issue(
        cfo, principal="cfo@meridianretail.example", agent_id="procure-01",
        budget_total=250000,
        allowed_tools={"saas_renewal": "software", "book_travel": "travel",
                       "order_supplies": "supplies"},
        allowed_domains=["*.figma.com", "*.salesforce.com",
                         "*.makemytrip.com", "*.officemart.example"],
        budget_categories={"travel": 60000, "software": 170000, "supplies": 40000},
        active_hours=(0, 24),          # keep the demo runnable at any hour
        max_actions_per_hour=30,
        require_approval_over=50000,
        ttl_hours=31 * 24)

    print(f"\n  Mandate {cert['id']} signed by the CFO (Ed25519, verifiable offline)")
    print(f"  budget 2,50,000 | travel<=60k software<=170k supplies<=40k | approval >50k")

    store = Store()               # Store('surety.db') persists across restarts
    guard = Guard(cert, store)

    banner("The agent's month")
    show("renew Figma, 38,400 (software)",
         guard.request("saas_renewal", domain="www.figma.com", amount=38400))
    show("book 2 flights BLR-BOM, 24,650 (travel)",
         guard.request("book_travel", domain="www.makemytrip.com", amount=24650))
    show("buy LinkedIn ads, 45,000  <- tool never granted",
         guard.request("buy_ads", domain="linkedin.com", amount=45000))
    show("chairs from unlisted vendor, 22,000  <- bad domain",
         guard.request("order_supplies", domain="quickdeals.biz", amount=22000))
    show("team offsite travel, 48,000  <- busts TRAVEL category",
         guard.request("book_travel", domain="www.makemytrip.com", amount=48000))

    d = guard.request("saas_renewal", domain="www.salesforce.com", amount=118000,
                      detail="annual Salesforce renewal")
    show("Salesforce renewal, 1,18,000  <- over threshold", d)
    if d.verdict == "ESCROW":
        print(f"      ... escrow {d.escrow_id} waits for a human (expires in 24h) ...")
        show("CFO approves from phone", guard.approve(d.escrow_id, "cfo@meridianretail.example"))

    show("AWS credits, 75,000  <- busts TOTAL budget",
         guard.request("saas_renewal", domain="www.salesforce.com", amount=75000))

    print(f"\n  spent {guard.spent:,.0f} / 2,50,000 | by category: " +
          ", ".join(f"{k} {v['spent']:,.0f}/{v['cap']:,.0f}"
                    for k, v in guard.category_state().items()))

    banner("The kill switch")
    guard.revoke()
    show("agent tries one more renewal after revocation",
         guard.request("saas_renewal", domain="www.figma.com", amount=1000))

    banner("The log survives scrutiny")
    ok, _ = store.verify_chain()
    n = len(store.audit_entries())
    print(f"\n  audit chain intact: {ok}  ({n} entries, each sealing the last)")
    print("  every decision above carries its full evidence list, e.g.:")
    last = store.audit_entries()[2]["body"]
    for e in last.get("evidence", [])[:4]:
        print("    .", e)

    banner("Offline verification (what a merchant sees)")
    from .verifier import verify_action
    res = verify_action(cert, tool="book_travel",
                        domain="www.makemytrip.com", amount=24650)
    for chk in res["checks"]:
        print(("  [ok] " if chk["passed"] else "  [X ] ") + chk["check"])
    print("\n  No API call, no shared secret: the mandate carries its own proof.")
    print("  That is the primitive the agent economy is missing.\n")
