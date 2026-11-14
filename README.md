# TraceLock

Tracelock is a minimal tamper-evident accountability layer for AI agents.

TraceLock is an OpenTelemetry `SpanProcessor` that takes `gen_ai.*` spans from an
instrumented agent, signs them (Ed25519), and appends them to an RFC 6962 (Certificate
Transparency style) Merkle ledger. A separate **witness** cosigns signed tree heads (STHs)
after checking consistency. A standalone **verifier** CLI then lets an auditor check an
exported trace using only public keys and witnessed tree heads.

```
agent --spans--> TraceLockSpanProcessor --event--> Ledger (SQLite + Merkle tree)
                                                     | signs each leaf (operator key)
                                                     | signs STHs (log key)
                                                     v
                      Witness process (own key, own dir): checks log signature + consistency proof,
                      cosigns, stores. Rejects forks/rollbacks with 409 and logs the evidence.
                                                     |
 exported trace + public keys + witnessed STHs  --> verify.py (standalone) --> JSON result --> report.html
```

## Architecture

See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for components, data formats, the witness protocol and the verifier's checks.


## Setup

See [HOWTORUN.md](docs/HOWTORUN.md) for more.


## Limitations

- **Tamper-evidence is not truthfulness.** A verified record shows the record was not altered
  after the fact. It does not show the agent told the truth, behaved well, or that the actions
  had the effects the record claims.
- **Actions that bypass instrumentation are not recorded.** TraceLock only sees spans handed to
  it. An action executed outside instrumentation leaves no trace, and nothing here detects that.
- **Events after the last witnessed STH can be truncated silently.** The checkpoint interval is
  the vulnerability window: the unwitnessed tail is protected only by per-event signatures. The verifier reports the tail but cannot prove it is complete. An attacker who
  withholds the latest witnessed STHs merely widens the tail.
- **A same-machine witness is a demo, not real independence.** Real assurance needs witnesses
  run by different parties on different infrastructure. The first STH is accepted on first use,
  and the witness HTTP endpoint is unauthenticated.
- **`gen_ai.*` semantic conventions are experimental,** so versions are pinned and every attribute
  name lives in one mapping table (`tracelock/processor.py`, marked "verify against current docs").
- **Compromise of all keys together defeats it.** If the log key, operator key and every witness
  are controlled by the attacker, history can be rewritten undetectably.
- Redaction is pattern-based (Bearer tokens, `gsk_`/`sk-` keys, `api_key`/`Authorization`
  pairs, sensitive field names, the literal `GROQ_API_KEY`); it cannot catch an arbitrary
  secret embedded in free text.
- Single writer: one ledger process per database, and the witness client assumes it is the only
  submitter. Out of scope by design: dashboards, multi-witness quorum, key rotation, per-event
  witness acknowledgements.


## References

1. Cygnux Labs. Tracekit: tamper-evident records of what your AI agents did (software, PyPI `tracekit-ai`). [https://pypi.org/project/tracekit-ai/1.2.0/](https://pypi.org/project/tracekit-ai/1.2.0/) . Documentation: [https://github.com/Cygnux-Labs/Tracekit/wiki/Concepts-Overview](https://github.com/Cygnux-Labs/Tracekit/wiki/Concepts-Overview) .
2. ghostfactory-art. Span Chain: tamper-evident audit trail and deterministic replay for AI agents (software). [https://github.com/ghostfactory-art/spanchain](https://github.com/ghostfactory-art/spanchain) .
3. Prismer AI. Signet: cryptographic receipts for AI agent tool calls (software). [https://github.com/prismer-ai/signet](https://github.com/prismer-ai/signet) .
4. hellothere012. NotaryOS: cryptographic receipt system for AI agent accountability (software). [https://github.com/hellothere012/notaryos](https://github.com/hellothere012/notaryos) .
5. World-999-Labs. Proof Layer: cryptographic governance receipts for AI agents, MCP server and offline verifier (software). [https://github.com/World-999-Labs/proof-layer](https://github.com/World-999-Labs/proof-layer) .
6. Sigil Notary: cryptographic audit trails for AI agents (software, PyPI). [https://pypi.org/project/sigil-notary/](https://pypi.org/project/sigil-notary/) .
7. attestroot: local-first, tamper-evident evidence for AI agent activity (software, PyPI). [https://pypi.org/project/attestroot/](https://pypi.org/project/attestroot/) .
8. Etch: trace, replay and verify every AI agent decision (product page, Product Hunt). [https://www.producthunt.com/posts/etch-9fc3d89c-889d-4c7b-b981-d07d73ebcd60](https://www.producthunt.com/posts/etch-9fc3d89c-889d-4c7b-b981-d07d73ebcd60) .
9. Qin, J., Schmotz, D., Prinzhorn, D., Beurer-Kellner, L., Prabhu, A., & Andriushchenko, M. LLM Agents Can Easily Tamper With Their Own Traces. arXiv:2609.30266, September 2026. [https://arxiv.org/abs/2609.30266](https://arxiv.org/abs/2609.30266)
10. Nian, Y., Yuan, A., Zhang, H., Li, J., Li, L., Hu, X., Wei, H., Xiao, X., Xiao, C., & Zhao, Y. Auditable Agents. arXiv:2604.05485, April 2026. [https://arxiv.org/abs/2604.05485](https://arxiv.org/abs/2604.05485)
11. Du, Z., & Chen, Y. AUDITA: Certified Auditing and Causal Attribution of Adverse Outcomes in Autonomous Multi-Agent Systems. arXiv:2608.22160, August 2026. [https://arxiv.org/abs/2608.22160](https://arxiv.org/abs/2608.22160)
12. Ojewale, V., Suresh, H., & Venkatasubramanian, S. Audit Trails for Accountability in Large Language Models. arXiv:2601.20727, January 2026. [https://arxiv.org/abs/2601.20727](https://arxiv.org/abs/2601.20727)
13. What Did Your AI Agent Actually Do? Building a Tamper-Evident Audit Trail (blog article, HackerNoon). [https://hackernoon.com/what-did-your-ai-agent-actually-do-building-a-tamper-evident-audit-trail](https://hackernoon.com/what-did-your-ai-agent-actually-do-building-a-tamper-evident-audit-trail) .
14. Building Verifiable AI Agent Audit Logs With Signed, Hash-Chained Records (blog article, HackerNoon). [https://hackernoon.com/building-verifiable-ai-agent-audit-logs-with-signed-hash-chained-record](https://hackernoon.com/building-verifiable-ai-agent-audit-logs-with-signed-hash-chained-record) .
15. Gravitee. Ledger anchoring for OpenTelemetry traces (article). [https://gravitee.io/corpus/gen-623/blockchain/ledger-anchoring-for-opentelemetry-traces.html](https://gravitee.io/corpus/gen-623/blockchain/ledger-anchoring-for-opentelemetry-traces.html) .


## More

[ARCHITECTURE.md](docs/ARCHITECTURE.md) · [THREAT_MODEL.md](docs/THREAT_MODEL.md) · [SECURITY.md](docs/SECURITY.md) ·
