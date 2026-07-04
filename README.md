# Surety

**The authorization and liability rail for AI agents.**

AI agents now spend money, book services, post publicly and file documents on humans' behalf. The human world solved delegated authority centuries ago (power of attorney, letters of credit, surety bonds). The agent world has none of it. Three questions nobody can answer today:

- **Authority** — a merchant receives an order from an agent. Can anyone prove a human authorized it?
- **Scope** — "my agent may spend up to 5,000 on travel this week, nothing else, anywhere." No mechanism carries that limit across tools and sites.
- **Liability** — the agent books the wrong thing. Who pays? There is no log that stands up, and no underwriter.

Surety is the missing rail: **delegation certificates** (a scoped, revocable, signed grant of authority), **enforcement middleware** (every tool call checked before it executes; out-of-scope calls blocked or escrowed for one-tap human approval), and a **tamper-evident audit log** (hash-chained; any edit is detectable). At scale, that log is actuarial data — the basis for bonding agents the way contractors are bonded.

## Quickstart

No dependencies beyond the Python 3.9+ standard library.

```bash
python demo.py
```

The demo issues a certificate (INR 5,000 travel budget, two allowed tools, two allowed domains, human approval required over INR 2,500), then watches an agent work:

```
book flight, INR 2100 (airindia.com)            -> [ALLOW]  in scope
book HOTEL, INR 1800  <- tool never granted     -> [BLOCK]  tool 'book_hotel' not in allowed_tools
book flight via shady-travel.biz                -> [BLOCK]  domain not in allowed_domains
book return flight, INR 2600                    -> [ESCROW] exceeds approval threshold
  human approves the escrowed booking           -> [ALLOW]  approved by you@example.com
book one more flight, INR 800                   -> [BLOCK]  would exceed budget
```

Then it demonstrates the point of the log: edit one entry, and the hash chain breaks at exactly that entry.

## Use as a library

```python
from surety import issue, Guard

cert = issue("you@example.com", secret, "my-agent",
             max_spend=5000, allowed_tools=["book_flight"],
             allowed_domains=["*.airline.com"], require_approval_over=2500)

guard = Guard(cert, secret)
decision = guard.request("book_flight", domain="www.airline.com", amount=2100)
if decision.verdict == "ALLOW":
    ...  # actually execute the tool call
```

Wrap your agent's tool dispatcher with `guard.request(...)` and you have enforcement plus an audit trail with ~10 lines of change. For MCP-based agents, the integration point is a proxy server that forwards in-scope calls and escrows the rest — see `docs/ARCHITECTURE.md`.

## Status and roadmap

This is a working concept prototype, deliberately zero-dependency.

- [x] Certificate format v1 (HMAC-signed), guard, escrow, hash-chained log
- [ ] Ed25519 keypairs so third parties verify certificates without the secret
- [ ] MCP proxy server (drop-in for any MCP tool server)
- [ ] Revocation registry + push revocation
- [ ] Merchant-side verification endpoint ("was this order authorized?")
- [ ] Underwriting pilot: premium priced from logged action history

## Why this matters

Enterprise agent deployments stall at pilot stage because legal and compliance cannot sign off on unbounded delegated action. The hands exist; the permission slip does not. Whoever holds the authorization and liability layer becomes the gateway of the agent economy.

## License

MIT
