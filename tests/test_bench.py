from bench.overhead import TimedTracer, format_tables, measure, run_benchmark, summarize
from opentelemetry.sdk.trace import TracerProvider


def test_benchmark_structure_and_table():
    r = run_benchmark(spans=40, intervals=(1, 5))
    assert r.spans == 40 and len(r.rows) == 4  # 2 intervals x {no witness, witness}
    assert [(x["interval"], x["witness"]) for x in r.rows] == [(1, False), (1, True), (5, False), (5, True)]
    for row in r.rows:
        assert row["stats"]["p95"] >= row["stats"]["p50"] > 0
        assert row["added"]["mean"] > 0  # the processor really costs something
    t = format_tables(r)
    assert "| STH interval N | Witness call | added p50 ms | added p95 ms | added mean ms |" in t
    assert "absolute milliseconds" in t and "%" not in t.split("Notes:")[0]


def test_measure_returns_exactly_the_requested_number_of_samples():
    assert len(measure(37, 1, None, False)) == 37
    assert len(measure(37, 1, 5, False)) == 37


def test_timed_tracer_is_exclusive_of_span_body():
    import time
    tt = TimedTracer(TracerProvider().get_tracer("x"))
    with tt.start_as_current_span("outer"):
        with tt.start_as_current_span("inner"):
            time.sleep(0.02)
    assert len(tt.sink) == 2 and max(tt.sink) < 5_000_000  # 20 ms body is not counted


def test_summarize_percentiles():
    s = summarize([1_000_000 * i for i in range(1, 101)])
    assert abs(s["p50"] - 50.5) < 1e-9 and abs(s["mean"] - 50.5) < 1e-9 and 95 <= s["p95"] <= 96
