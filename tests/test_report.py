import json

from attacks.tamper import scenario_2, run_scenario
from demo.agent_scripted import produce_artifacts
from tracelock.report import main as report_main, render_html
from tracelock.verify import verify_files


def test_clean_report(tmp_path):
    art = produce_artifacts(tmp_path)
    res = verify_files(**art.verify_args())
    html = render_html(res)
    assert "<div class='banner pass'>PASS" in html
    assert "What this does NOT prove" in html and "not a truthful one" in html
    assert "no unwitnessed tail" in html
    assert html.count("✓ pass") == art.n_events and "✗ fail" not in html.split("<h2>Events</h2>")[1].split("</table>")[0]
    assert "<script" not in html.lower() and "http://" not in html and "https://" not in html
    assert "<style>" in html and "stylesheet" not in html  # inline CSS only


def test_failed_report_highlights_range_and_tail(tmp_path):
    art = produce_artifacts(tmp_path / "base", sth_interval=6, end_session=False)  # leaves a tail
    res = verify_files(**art.verify_args())
    html = render_html(res)
    assert "banner pass" in html and "unwitnessed tail" in html.lower()
    assert "class='tail'" in html and "event(s), seq 12–15" in html
    base = produce_artifacts(tmp_path / "b2")
    row = run_scenario(scenario_2, tmp_path / "s", base)
    bad = render_html(row.result)
    lo = row.result["first_broken_seq_range"][0]
    assert "<div class='banner fail'>FAIL" in bad
    assert f"First broken seq range: {lo}" in bad and "range" in bad
    assert "class='bad range" in bad  # the broken event's row is both failed and range-highlighted
    assert "✗ fail" in bad and "gap" in bad
    assert "<script" not in bad.lower()


def test_html_escaping_of_untrusted_fields(tmp_path):
    art = produce_artifacts(tmp_path)
    res = verify_files(**art.verify_args())
    res["events"][0]["name"] = "<script>alert(1)</script>"
    res["events"][0]["issues"] = ["<img src=x onerror=alert(1)>"]
    res["events"][0]["ok"] = False
    res["checks"]["trace_format"]["detail"] = "<b>x</b>"
    html = render_html(res)
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html
    assert "<img src=x" not in html and "<b>x</b>" not in html


def test_cli_writes_a_file(tmp_path):
    art = produce_artifacts(tmp_path / "a")
    (tmp_path / "r.json").write_text(json.dumps(verify_files(**art.verify_args())))
    assert report_main(["--result", str(tmp_path / "r.json"), "--out", str(tmp_path / "r.html")]) == 0
    assert (tmp_path / "r.html").read_text(encoding="utf-8").startswith("<!doctype html>")
