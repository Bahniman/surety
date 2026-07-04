"""Surety demo: a travel agent with a signed budget, watched by the Guard.

Run:  python demo.py
No dependencies beyond the standard library.
"""
from surety import issue, Guard, AuditLog

W = 74


def banner(text):
    print("\n" + "=" * W)
    print(text)
    print("=" * W)


def show(step, decision):
    print(f"  {step:<52} -> [{decision.verdict}] {decision.reason}")


def main():
    banner("SURETY DEMO: who authorized what, enforced in line")

    # 1. The human issues a scoped, signed delegation certificate.
    secret = "principal-secret-demo-only"
    cert = issue(
        principal="you@example.com", secret=secret, agent_id="travel-agent-01",
        max_spend=5000, currency="INR",
        allowed_tools=["search_flights", "book_flight"],
        allowed_domains=["*.makemytrip.com", "*.airindia.com"],
        ttl_hours=168,
        require_approval_over=2500,
    )
    print(f"\nCertificate {cert['id']} issued by {cert['principal']}")
    print(f"  budget INR {cert['scope']['max_spend']:.0f} | tools {cert['scope']['allowed_tools']}")
    print(f"  domains {cert['scope']['allowed_domains']} | human approval over INR 2500")

    log = AuditLog()
    guard = Guard(cert, secret, log)

    banner("The agent goes to work")

    show("search flights BLR-DEL (makemytrip.com)",
         guard.request("search_flights", domain="www.makemytrip.com",
                       detail="BLR-DEL 14 Jul"))

    show("book flight, INR 2100 (airindia.com)",
         guard.request("book_flight", domain="booking.airindia.com",
                       amount=2100, detail="AI-505 economy"))

    show("book HOTEL, INR 1800  <- tool never granted",
         guard.request("book_hotel", domain="www.makemytrip.com", amount=1800))

    show("book flight via shady-travel.biz  <- domain not allowed",
         guard.request("book_flight", domain="shady-travel.biz", amount=900))

    d = guard.request("book_flight", domain="www.makemytrip.com",
                      amount=2600, detail="return DEL-BLR, refundable")
    show("book return flight, INR 2600  <- over approval threshold", d)

    if d.verdict == "ESCROW":
        print(f"\n  ... escrow {d.escrow_id} is waiting for the human ...")
        show("human approves the escrowed booking",
             guard.approve(d.escrow_id, approver="you@example.com"))

    show("book one more flight, INR 800  <- would bust the budget",
         guard.request("book_flight", domain="www.makemytrip.com", amount=800))

    print(f"\n  spent INR {guard.spent:.0f} of {cert['scope']['max_spend']:.0f}"
          f" | remaining INR {guard.remaining:.0f}")

    banner("The log cannot be quietly edited")
    ok, _ = log.verify_chain()
    print(f"\n  audit chain intact: {ok}  ({len(log.entries)} entries, hash-chained)")

    victim = next(e for e in log.entries if e.get("verdict") == "BLOCK")
    print(f"  an insider edits entry #{victim['seq']} to hide the blocked hotel attempt...")
    victim["verdict"] = "ALLOW"
    ok, bad = log.verify_chain()
    print(f"  audit chain intact: {ok}  (chain breaks at entry #{bad})")

    banner("That is Surety")
    print("""
  A signed certificate said what this agent could do. Middleware enforced
  it on every call. The log proves the history to anyone, later.
  Authority, scope, and accountability: the missing rail of the agent economy.
""")


if __name__ == "__main__":
    main()
