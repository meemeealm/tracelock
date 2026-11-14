# Security Policy

## Status

TraceLock is a **reference implementation**. Read [THREAT_MODEL.md](THREAT_MODEL.md) and the Limitations section of the README.

## What counts as a vulnerability

- The verifier returns **PASS** for a trace that was edited, had events deleted or reordered, or was
  truncated before the last witnessed STH, with the correct public keys supplied.
- The witness cosigns an STH that is inconsistent with, smaller than, or conflicts with one it
  already cosigned.
- A secret (API key, bearer token) reaches the ledger, payload table, export or a fixture despite
  the documented redaction patterns.
- The standalone verifier imports or executes code outside the standard library and `cryptography`.
- A flaw in the RFC 6962 proof generation or verification.

## What does not count

These are documented limitations, not vulnerabilities: silent truncation of events after the last
witnessed STH; actions that bypass instrumentation; a witness that is not independent; compromise
of the log, operator and witness keys together; secrets that redaction patterns cannot recognise;
the unauthenticated witness endpoint.

## Handling keys

- `*.key` files are private keys. They are written with owner-only permissions. Never commit them
  (`.gitignore` excludes them) and never share them.
- The **witness key must be held by a different party** from the agent operator, on different
  infrastructure. A witness on the same machine is a demo.
- Distribute the public keys (`log.pub`, `agent.pub`, `witness.pub`) to auditors **out of band**
  (not alongside the trace they are checking).
