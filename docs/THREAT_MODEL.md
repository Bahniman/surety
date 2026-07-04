# Surety — threat model

What can go wrong, who tries it, and what the design does about it. Written
the way a security review would ask for it: attacker, attack, mitigation,
residual risk.

## Assets

1. The principal's authority (the ability to spend / act in their name)
2. The audit history (evidence of what happened)
3. The spend state (budgets consumed so far)

## Adversaries

| Adversary | Motivation |
|---|---|
| A1. Compromised or misaligned agent | Exceed its mandate (overspend, wrong vendor, prompt-injected goals) |
| A2. Malicious counterparty (merchant) | Get paid for actions the principal never authorized |
| A3. Insider at the operator | Hide or alter what an agent did after the fact |
| A4. External attacker | Steal the principal's signing key, forge mandates |
| A5. The principal themselves | Repudiate an action they did authorize ("I never approved that") |

## Attacks and mitigations

### A1: Agent exceeds its mandate
- **Attack:** call a tool outside scope, overspend a category, hammer requests.
- **Mitigation:** the guard evaluates every call against the signed mandate
  (tool→category map, domain allow-list, per-category and total budgets, rate
  limit, active hours). Checks run in a fixed order; first failure wins;
  the failure is logged with full evidence.
- **Residual:** if the agent can reach tools *around* the guard, nothing here
  applies. Production deployment therefore puts the guard at the tool-server
  boundary (MCP proxy), not inside the agent process. This is the single most
  important deployment rule.

### A1b: Agent splits a big action into many small ones (structuring)
- **Attack:** stay under `require_approval_over` by splitting 118k into 3×39k.
- **Mitigation:** category and total budgets still bind; the rate limit caps
  velocity; the audit log makes the pattern visible.
- **Residual:** within-budget structuring below threshold is permitted by
  design (the principal set the budget). Anomaly detection on the log is the
  production answer, and is exactly the data the underwriting layer needs.

### A2: Merchant claims authorization that never existed
- **Attack:** fabricate or replay a mandate.
- **Mitigation:** Ed25519 signatures verify offline against the principal's
  public key; tampering any field kills the signature (tested). Expiry bounds
  replay in time. Production adds per-action nonces + guard-signed receipts
  so a specific *action* (not just the mandate) is provable.
- **Residual (prototype):** no per-action receipt yet; documented gap.

### A3: Insider edits the history
- **Attack:** alter or delete an audit row after the fact (e.g. hide a block).
- **Mitigation:** hash-chained log; `verify_chain()` finds the first broken
  link (tested against direct SQLite tampering). Production anchors the chain
  head to an external timestamping service periodically, so even deleting the
  whole database is detectable.
- **Residual:** an insider with write access *between* anchor points can
  truncate the tail; anchor frequency bounds the exposure window.

### A4: Key theft
- **Attack:** steal the principal's seed, issue arbitrary mandates.
- **Mitigation:** revocation is immediate and logged; short TTLs are the
  default posture (mandates are cheap to reissue). Production keeps principal
  keys in platform keystores/HSMs and supports key rotation with overlapping
  validity.
- **Residual:** window between theft and revocation. Rate limits and
  thresholds cap the damage rate inside that window — this is exactly the
  argument an underwriter prices.

### A5: Principal repudiates
- **Attack:** "I never signed that mandate / approved that escrow."
- **Mitigation:** the mandate carries the principal's signature; approvals
  are logged with approver identity in the tamper-evident chain. Ed25519
  signatures are non-repudiable to the strength of key custody.
- **Residual:** "my key was stolen" collapses to A4; custody policy decides.

## Out of scope (prototype), on the roadmap
- Guard-signed action receipts (merchant-verifiable per-action proof)
- External chain anchoring (e.g. RFC 3161 timestamping)
- Key rotation and multi-sig mandates (two officers above a threshold)
- Anomaly detection over the audit stream
