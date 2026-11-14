# Threat Model

## What is being protected

The **integrity of an agent's recorded history**: which model calls and tool calls were recorded,
in what order, with which payload hashes. Not the agent's honesty or the correctness of its actions.

## Parties and what they hold

| Party | Holds | Trusted for |
|---|---|---|
| Operator (runs the agent and ledger) | operator key, log key, ledger database | recording; **not** trusted by the auditor |
| Witness (independent) | witness key, its own STH store | remembering and cosigning tree heads |
| Auditor | public keys (obtained out of band), the exported trace, witnessed STHs | nothing: re-computes everything |

## Attackers and outcomes

| Attacker | Capability | Result |
|---|---|---|
| A. Outsider / file tamperer | Can modify the exported trace or STH file; has no keys | Edits, deletions, reordering, truncation before the last witnessed STH are **detected**; forged STHs fail signature checks |
| B. Operator after the fact | Has operator and log keys; no witness key | A full, internally perfect rewrite is **detected** because earlier witnessed STHs no longer match, and the witness refuses to cosign the rewrite |
| C. Operator, truncating the tail | Same as B, removes events after the last witnessed STH | **Not detected** (unwitnessed tail). The checkpoint interval is the exposure window |
| D. Operator, bypassing instrumentation | Performs actions without emitting spans | **Not detected**: nothing was recorded |
| E. Colluding operator and witness (or all keys stolen) | Controls every key | **Out of scope**: history can be rewritten undetectably |

These rows correspond to the six scenarios in `attacks/tamper.py`.

## Assumptions

1. The witness is **independent** of the operator and keeps its key and data separate. On one
   machine it is a demo.
2. Auditors obtain the public keys through a channel the attacker does not control.
3. The first STH a witness sees is accepted on first use (nothing earlier exists to compare with).
4. Cryptographic primitives hold: SHA-256, Ed25519.

## Not guaranteed

- **Truthfulness or safety of the agent.** A tamper-evident record can faithfully record a lie.
- **Completeness.** Only spans handed to TraceLock are recorded.
- **The unwitnessed tail** (events after the last witnessed STH).
- **Trusted time.** Timestamps are asserted by the agent host and the log; the witness does not add
  its own. Do not treat them as proof of when something happened.
- **Payload confidentiality.** Exporting a trace *with* payloads discloses them. Payload *hashes*
  of short or guessable inputs can be brute-forced by anyone who has the trace. Redaction is
  pattern-based and cannot recognise every secret.
- **Availability.** A witness that is down means checkpoints are skipped (recorded in
  `witness_errors`) and the unwitnessed tail grows. Denial of service is out of scope.

## Residual risks to manage operationally

Keep the witness key and storage away from the operator; choose a checkpoint interval that matches
how large an unwitnessed tail you can tolerate; check `witness_errors` after every run; never commit
`.key` files or `.env`.
