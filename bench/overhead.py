"""Overhead microbenchmark: added milliseconds per span from the TraceLock processor.

What is timed
  Each span's lifecycle cost (entering + leaving ``start_as_current_span``), EXCLUDING the
  span body. Nested spans therefore never double-count their children, and the processor's
  work (ledger append, signing, SQLite commit, STH issue, witness HTTP call) all happens in
  that window, because the processor runs synchronously in ``on_end``.
  "Added" = (with TraceLock) - (same workload, no processor), per statistic.

Workload: the scripted agent and its mock tools (no network), seeded. Spans are collected
until ``spans`` samples exist (whole sessions are run, then the list is cut to ``spans``).
Warm-up sessions run first and are discarded. The witness, when enabled, is an in-process
HTTP server on loopback (shares the GIL with the benchmark: pessimistic) -- not a network hop.

Run:  python -m bench.overhead [--spans 1000] [--intervals 1,5,20,50]
"""
from __future__ import annotations

import argparse
import statistics
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from opentelemetry.sdk.trace import TracerProvider

from demo.agent_scripted import DEFAULT_SEED, run_session
from tracelock.ledger import Ledger
from tracelock.processor import TraceLockSpanProcessor
from tracelock.signing import generate_private_key
from tracelock.witness import Witness, WitnessClient, make_server, serve_in_thread, server_url

WARMUP_SESSIONS = 3


class _TimedSpan:
    def __init__(self, cm: Any, sink_ref: "TimedTracer") -> None:
        self._cm, self._owner, self._enter_ns = cm, sink_ref, 0

    def __enter__(self) -> Any:
        t0 = time.perf_counter_ns()
        span = self._cm.__enter__()
        self._enter_ns = time.perf_counter_ns() - t0
        return span

    def __exit__(self, *exc: Any) -> Any:
        t0 = time.perf_counter_ns()
        result = self._cm.__exit__(*exc)
        self._owner.sink.append(self._enter_ns + time.perf_counter_ns() - t0)
        return result


class TimedTracer:
    """Wraps a tracer; records per-span lifecycle time (ns) in ``sink``."""

    def __init__(self, tracer: Any) -> None:
        self._tracer = tracer
        self.sink: list[int] = []

    def start_as_current_span(self, name: str, *a: Any, **k: Any) -> _TimedSpan:
        return _TimedSpan(self._tracer.start_as_current_span(name, *a, **k), self)


def measure(spans: int, seed: int, interval: int | None, witness: bool) -> list[int]:
    """Per-span lifecycle times in ns. ``interval=None`` means no TraceLock processor."""
    with tempfile.TemporaryDirectory() as d:
        provider = TracerProvider()
        ledger = server = None
        if interval is not None:
            log_key = generate_private_key()
            ledger = Ledger(Path(d) / "bench.db", log_key, generate_private_key(), sth_interval=interval)
            if witness:
                server = make_server(Witness(Path(d) / "witness", log_key.public_key()))
                serve_in_thread(server)
                ledger.sth_hook = WitnessClient(server_url(server), ledger.consistency_proof).submit
            provider.add_span_processor(TraceLockSpanProcessor(ledger, "bench"))
        tracer = TimedTracer(provider.get_tracer("bench"))
        try:
            for k in range(WARMUP_SESSIONS):  # warm-up: imports, caches, connections, JIT-ish effects
                run_session(tracer, seed=10_000 + k)
            tracer.sink = []
            k = 0
            while len(tracer.sink) < spans:
                run_session(tracer, seed=seed + k)
                k += 1
            if ledger is not None and interval and witness:
                assert not ledger.hook_errors, ledger.hook_errors[:3]  # a silent witness failure would flatter the numbers
            return tracer.sink[:spans]
        finally:
            if ledger is not None:
                ledger.close()
            if server is not None:
                server.shutdown()
                server.server_close()


def summarize(ns: list[int]) -> dict[str, float]:
    ms = [x / 1e6 for x in ns]
    return {"p50": statistics.median(ms), "p95": statistics.quantiles(ms, n=100, method="inclusive")[94],
            "mean": statistics.fmean(ms)}


@dataclass
class BenchResult:
    spans: int
    baseline: dict[str, float]
    rows: list[dict[str, Any]]  # interval, witness, stats (absolute with), added (with - baseline)


def run_benchmark(spans: int = 1000, intervals: tuple[int, ...] = (1, 5, 20, 50), seed: int = DEFAULT_SEED) -> BenchResult:
    baseline = summarize(measure(spans, seed, None, False))
    rows = []
    for interval in intervals:
        for witness in (False, True):
            stats = summarize(measure(spans, seed, interval, witness))
            rows.append({"interval": interval, "witness": witness, "stats": stats,
                         "added": {k: stats[k] - baseline[k] for k in stats}})
    return BenchResult(spans, baseline, rows)


def _sdk_note() -> str:
    try:
        from importlib.metadata import version
        return f"opentelemetry-sdk {version('opentelemetry-sdk')}"
    except Exception:
        return "opentelemetry-sdk version unknown (not installed as a distribution)"


def format_tables(r: BenchResult) -> str:
    b = r.baseline
    out = [f"Spans per configuration: {r.spans} (after warm-up). Python {sys.version.split()[0]}; {_sdk_note()}.",
           "All values are absolute milliseconds per span (no percentages).", "",
           "Baseline (no TraceLock processor), span lifecycle cost:", "",
           "| p50 ms | p95 ms | mean ms |", "|---|---|---|",
           f"| {b['p50']:.4f} | {b['p95']:.4f} | {b['mean']:.4f} |", "",
           "Added per event by TraceLock (with minus baseline):", "",
           "| STH interval N | Witness call | added p50 ms | added p95 ms | added mean ms |", "|---|---|---|---|---|"]
    for row in r.rows:
        a = row["added"]
        out.append(f"| {row['interval']} | {'yes' if row['witness'] else 'no'} | "
                   f"{a['p50']:.4f} | {a['p95']:.4f} | {a['mean']:.4f} |")
    out += ["", "Notes: p50/p95 are differences of percentiles, so they can sit close to or below 0 only when "
            "noise exceeds the effect. The mean includes the amortised cost of STH issuance and witness calls; "
            "p95 only shows them when they occur in more than 5% of events (small N)."]
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="TraceLock overhead microbenchmark")
    ap.add_argument("--spans", type=int, default=1000)
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED)
    ap.add_argument("--intervals", default="1,5,20,50")
    args = ap.parse_args(argv)
    print(format_tables(run_benchmark(args.spans, tuple(int(x) for x in args.intervals.split(",")), args.seed)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
