# Surety — architecture

## The primitive

```
principal (human)
   |  signs
   v
delegation certificate  { agent, scope: {budget, tools, domains, approval threshold}, expiry }
   |  presented by
   v
agent  --- every tool call --->  GUARD (middleware)
                                   |-- in scope        -> execute, log
                                   |-- over threshold  -> ESCROW, notify human, log
                                   |-- out of scope    -> BLOCK, log
                                   v
                          hash-chained audit log  ->  (later) actuarial data -> underwriting
```

## Components in this prototype

| Component | File | Notes |
|---|---|---|
| Certificate | `surety/certificate.py` | Canonical-JSON body, HMAC-SHA256 signature, revocation by re-signing |
| Guard | `surety/guard.py` | Scope checks (tool, domain fnmatch, cumulative budget, per-action threshold), escrow queue with approve/deny, re-check on approval |
| Audit log | `surety/audit.py` | Append-only, each entry hashes its predecessor; `verify_chain()` finds the first tampered entry |

## Prototype shortcuts, and the production answer

| Shortcut here | Production design |
|---|---|
| HMAC with principal's secret (verifier needs the secret) | Ed25519 keypair; certificate carries public key; any counterparty verifies offline |
| In-memory escrow + log | Durable store; escrow notifications via push/app; log anchored periodically to an external timestamping service |
| Guard runs in the agent's process | Guard runs as an MCP proxy in front of tool servers, so the agent cannot bypass it; mutual auth between proxy and tools |
| Spend tracked per guard instance | Spend tracked per certificate across all sessions, server-side |
| Trust the principal's clock | Signed timestamps; expiry checked against server time |

## MCP integration sketch

MCP standardizes how agents call tools, which makes it the natural choke point.
The proxy pattern:

```
agent  ->  surety-proxy (MCP server)  ->  real MCP tool servers
```

The proxy re-exports every tool of the upstream servers with identical schemas.
On `tools/call`, it maps the call to (tool, domain, amount) using per-tool
extractors, runs `guard.request(...)`, and either forwards, blocks with a
structured error the agent can relay to the user, or parks the call and
returns an escrow ticket. Approval resumes the parked call.

## The long game

1. **Standard**: publish the certificate format; reference implementations in Python/TS.
2. **Verification network**: merchants query "was this authorized?" like they query 3-D Secure today.
3. **Underwriting**: with millions of logged, certified actions, loss rates become priceable. Agents get bonded; bonded agents get accepted where unbonded ones are refused. That flywheel is the business.
