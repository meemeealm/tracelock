# How to Run

## Use it in your own agent (as library)

```bash
pip install .                 # from this repo; installs the `tracelock` package and 3 commands
```

```python
import tracelock

# 1) once: create keys, then start a witness with log.pub (ideally on another machine)
tracelock.init_keys("tracelock_data")        # writes tracelock_data/keys/{log,agent}.{key,pub}
#    tracelock-witness serve --data-dir witness_data --log-pubkey tracelock_data/keys/log.pub --port 8800

# 2) in your app: one call wires ledger + processor + witness client
tl = tracelock.setup("tracelock_data", witness_url="http://witness-host:8800", sth_interval=20)
tracer = tl.tracer()          # your agent emits gen_ai.* spans through this
...                           # run the agent
out = tl.export()             # ends the session, writes trace.jsonl, fetches witnessed STHs
assert not tl.witness_errors  # every checkpoint was accepted by the witness
tl.close()
```

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt        # or: make install
```

## One-command demo

```bash
python -m demo.run_all        # or: make demo
```

Starts the **witness as a separate OS process** (own key, own data dir), runs the seeded
offline scripted agent, exports the trace, runs the standalone verifier, and writes
`out/run_all/report.html` (open it in a browser) plus `verification.json`. Exit code 0 = PASS.
The random seed is fixed (`DEFAULT_SEED = 1234`); override with `--seed`.

## Verify it yourself on your laptop

This is the real test. Everything runs locally. Steps 1-5 need no API key and no network (after
installing). Budget about 15 minutes.

**What you need:** Python 3.11 or newer and `pip`.

### Step 1: install

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt
python -m pip install -e .
```

If pip cannot find a pinned version, edit that line in `requirements.txt` (the pins were not checked
against PyPI) and tell us which one.

### Step 2: run the test suite

```bash
python -m pytest -q
```

Expect every test to pass and **none skipped**. A skipped `test_real_otel_sdk_end_to_end` means
OpenTelemetry is not installed in this environment. That test runs the whole recorder against the
real OpenTelemetry SDK and is the most important one.

### Step 3: run the clean end-to-end demo

```bash
python tasks.py demo
```

Expect `verifier: PASS`, eight checks listed as PASS, and a file `out/run_all/report.html`. Open it
in a browser: green PASS banner, checks table, event list. The witness ran as a separate OS process.
(No `make` needed; `tasks.py` works on Windows, macOS and Linux.)

### Step 4: watch tampering get caught

```bash
python tasks.py attacks
```

Expect the six-row table: rows 1, 2, 3 and 5 `DETECTED`, rows 4 and 6 `NOT DETECTED`, and the line
`All outcomes match expectations: yes.` The two NOT DETECTED rows are known limitations, not failures.

### Step 5: tamper with a trace by hand

Run the demo (Step 3), then verify the untouched files yourself. This command works on every OS:

```bash
python -m tracelock.verify --trace out/run_all/trace.jsonl --log-pubkey out/run_all/keys/log.pub --agent-pubkey out/run_all/keys/agent.pub --witness-pubkey out/run_all/witness_data/witness.pub --witnessed-sths out/run_all/witnessed_sths.json
```

It prints JSON ending with `"overall": "PASS"` and exits with code 0. Now try to cheat:

1. Copy `out/run_all/trace.jsonl` to `trace_edited.jsonl` and open it in a text editor.
2. **Edit:** change one word inside one line (for example the text of a `"name"` value). Save.
3. Re-run the command above with `--trace trace_edited.jsonl`. Expect `"overall": "FAIL"`, exit code 1,
   and `event_signatures` plus `merkle_root_vs_witnessed_sths` failing.
4. **Delete:** restore the copy, delete one whole line in the middle, save, re-run. Expect `FAIL`
   with `seq_continuity` naming the missing seq.
5. **Truncate:** restore the copy, delete the last three lines, re-run. Expect `FAIL` from
   `merkle_root_vs_witnessed_sths` ("trace has only N events").
6. Render the failing result: add `--out result.json` to the command, then
   `python -m tracelock.report --result result.json --out report_failed.html` and open it.

Exit codes: `0` PASS, `1` FAIL, `2` bad input (missing file, bad key).

### Step 6: record own agent

```bash
python examples/quickstart.py
```

This records a small stand-in agent, has it witnessed on localhost, and verifies it (`verifier: PASS`).
Then replace `fake_agent` in that file with the real agent, anything that emits OpenTelemetry spans
with `gen_ai.*` attributes through `tl.tracer()` works. Real use needs the witness on a **different
machine** . After a run, always check
`tl.witness_errors`, and repeat the tamper experiments from Step 5 on exported trace.

### Step 7 (optional): a real LLM

Copy `.env.example` to `.env`, set the key and model for OpenAI or Groq, then
`python tasks.py openai` (or `groq`). The model's replies are real; the three tools are still mocks.
Expect `verifier: PASS`. If it fails, see [LLM demo](#llm-demo-openai-or-groq-needs-network).

### Step 8 (optional): measure the overhead on your machine

```bash
python tasks.py bench
```

Absolute milliseconds added per event at several checkpoint intervals. The result depends mostly on your
disk (every append is a synchronous SQLite commit), so use your own numbers to choose `sth_interval`.


## Tests

```bash
pytest -q                     # or: make test
```

All tests run offline. The Merkle tests are the most rigorous: hand-computed roots for sizes
1-8, the Google CT reference roots, and every inclusion and consistency proof up to size 32
checked against an independent brute-force recompute (plus corrupted-proof rejection).

## Tamper scenarios

```bash
python -m attacks.tamper      # or: make attacks
```

Operates on **copies** of the exported artifacts. Output of the last run:

| # | Scenario | Expected | Actual | Caught by |
|---|---|---|---|---|
| 1 | Edit an event's content (no signing key) | DETECTED | DETECTED | `event_signatures`, `merkle_root_vs_witnessed_sths` |
| 2 | Delete a mid-log event | DETECTED | DETECTED | `seq_continuity`, `merkle_root_vs_witnessed_sths`, `session_end_counts` |
| 3 | Truncate tail before the last witnessed STH | DETECTED | DETECTED | `merkle_root_vs_witnessed_sths` |
| 4 | Truncate tail after the last witnessed STH | NOT DETECTED | NOT DETECTED | — (known limitation) |
| 5 | Full rewrite; attacker holds log + operator keys, not the witness key | DETECTED | DETECTED | `merkle_root_vs_witnessed_sths` |
| 6 | Event never emitted (silent drop / instrumentation bypass) | NOT DETECTED | NOT DETECTED | — (known limitation) |

Rows 4 and 6 are **honest known limitations, not bugs** (see below). In scenario 5 every
signature, hash and STH the attacker controls is internally perfect; only the witnessed
checkpoints expose the rewrite, and the witness itself refuses to cosign the rewritten heads
(409). The verifier names the check that caught each case and the first broken seq range.

## Overhead benchmark

```bash
python -m bench.overhead      # or: make bench
```

Scripted agent and mock tools, no network, 1000 spans per configuration after warm-up, STH
interval N = 1, 5, 20, 50, with and without the witness call. Reports **absolute added
milliseconds per event** at p50 / p95 / mean (added = with TraceLock minus the same workload
without). Numbers depend heavily on your disk (every append is a synchronous SQLite commit)
and on the witness being in-process loopback, so run it on your own machine.

## Running the verifier 

```bash
python tracelock/verify.py --trace trace.jsonl --log-pubkey keys/log.pub --agent-pubkey keys/agent.pub \
    --witness-pubkey witness_data/witness.pub --witnessed-sths witnessed_sths.json --out result.json
python -m tracelock.report --result result.json --out report.html
```

`verify.py` is standalone, it imports only the standard library and `cryptography` and carries
its own copy of the RFC 6962 verification code (a test cross-checks it against `merkle.py`).
It checks: per-event signatures; seq continuity; recomputed Merkle root vs every witnessed STH;
consistency between successive witnessed STHs (re-checked from proofs stored by the witness);
`session_end` counts; payload hashes (missing payloads are reported as "payload redacted", not
tampering); plus STH signatures. It also reports the **unwitnessed tail**. Exit codes: 0 PASS,
1 FAIL, 2 bad input.

Note: the verifier needs the **agent/operator public key** in addition to the log and witness
keys, because each event is signed by the operator key.

## LLM demo: OpenAI or Groq 

```bash
cp .env.example .env     # set the key + model for your provider (verify model names against its docs)
python tasks.py openai   # or: python -m demo.agent_groq --provider openai --record
python tasks.py groq     # or: python -m demo.agent_groq --provider groq   --record
```

`.env` settings:

| Provider | Variables |
|---|---|
| `groq` (default) | `GROQ_API_KEY`, `GROQ_MODEL` |
| `openai` | `OPENAI_API_KEY`, `OPENAI_MODEL`, optional `OPENAI_BASE_URL` (proxy or compatible server) |

Pick the provider with `--provider` or `LLM_PROVIDER` in `.env`. Both use the same OpenAI client and
the same tool-calling loop (same three tools, max 10 steps, exponential backoff on 429/5xx). It emits
manual `gen_ai.*` spans, runs the full pipeline, and `--record` saves the spans to `demo/fixtures/`
for offline replay. Keys are read from the environment only, never stored, and redacted from payloads
before hashing (`GROQ_API_KEY` and `OPENAI_API_KEY` literals, plus `gsk_` / `sk-` token patterns).
The chosen model must support tool/function calling. The OpenTelemetry OpenAI instrumentation package
is not used (not in the pinned dependencies).