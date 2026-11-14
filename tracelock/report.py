"""Static HTML report from the verifier's JSON output.

One self-contained file: inline CSS, no JavaScript, no external resources.
Reads only the verifier's JSON, so it can be generated anywhere.

    python -m tracelock.report --result verification.json --out report.html
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any

CSS = """
:root{--bg:#fff;--fg:#1d2330;--muted:#5b6475;--line:#d9dde5;--pass:#0b7a3b;--passbg:#e4f5ea;
--fail:#b3261e;--failbg:#fde8e6;--warn:#8a5a00;--warnbg:#fff4d6;--tail:#e8eefc;--card:#f7f8fa}
*{box-sizing:border-box}body{margin:0;padding:24px;background:var(--bg);color:var(--fg);
font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1100px;margin:0 auto}h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 8px}
.sub{color:var(--muted);margin:0 0 16px}
.banner{padding:18px 22px;border-radius:10px;font-size:26px;font-weight:700;letter-spacing:.5px;border:2px solid}
.banner small{display:block;font-size:14px;font-weight:400;letter-spacing:0;margin-top:2px}
.banner.pass{background:var(--passbg);color:var(--pass);border-color:var(--pass)}
.banner.fail{background:var(--failbg);color:var(--fail);border-color:var(--fail)}
.callout{margin:12px 0;padding:12px 16px;border-radius:8px;border:1px solid var(--line);background:var(--card)}
.callout.broken{background:var(--failbg);border-color:var(--fail)}
.callout.tail{background:var(--tail);border-color:#9db4ee}
.callout.limits{background:var(--warnbg);border-color:#e0b84a}
.callout ul{margin:6px 0 0 18px;padding:0}
table{border-collapse:collapse;width:100%;font-size:14px}
th,td{border:1px solid var(--line);padding:5px 8px;text-align:left;vertical-align:top}
th{background:var(--card)}code,.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px}
.badge{display:inline-block;padding:1px 8px;border-radius:99px;font-weight:600;font-size:12px}
.badge.PASS{background:var(--passbg);color:var(--pass)}.badge.FAIL{background:var(--failbg);color:var(--fail)}
.badge.SKIP{background:var(--warnbg);color:var(--warn)}
tr.bad td{background:var(--failbg)}tr.range td{box-shadow:inset 0 0 0 9999px rgba(179,38,30,.10);font-weight:600}
tr.tail td{background:var(--tail)}
.mark{font-weight:700;white-space:nowrap}.mark.ok{color:var(--pass)}.mark.no{color:var(--fail)}
.muted{color:var(--muted)}.scroll{overflow-x:auto}
footer{margin:28px 0 0;color:var(--muted);font-size:13px}
"""

NOT_PROVEN = [
    "That the agent told the truth, behaved well, or that its actions had the effects the record claims. "
    "A tamper-evident record is not a truthful one.",
    "That the record is complete. Actions that bypass the instrumentation were never recorded and "
    "cannot be detected here.",
    "Anything about events after the last witnessed STH (the unwitnessed tail). They can be truncated "
    "silently; the checkpoint interval is the vulnerability window.",
    "That the witness is independent. A witness on the same machine or under the same control is a demo, "
    "not real independence.",
    "Anything beyond what the supplied keys and witnessed STHs attest. If the log key, operator key and "
    "every witness are compromised together, history can be rewritten undetectably.",
    "That the gen_ai.* attributes mean what you expect: the semantic conventions are experimental.",
]


def _ts(ns: Any) -> str:
    try:
        return datetime.fromtimestamp(int(ns) / 1e9, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (TypeError, ValueError, OverflowError, OSError):
        return "unknown"


def _rng(r: Any) -> str:
    return "—" if not r else (f"{r[0]}" if r[0] == r[1] else f"{r[0]}–{r[1]}")


def _e(x: Any) -> str:
    return escape("" if x is None else str(x))


def _checks_table(result: dict[str, Any]) -> str:
    rows = []
    for name, c in result["checks"].items():
        extra = []
        for f in c.get("failures", []):
            extra.append(f"<li class='mono'>{_e(json.dumps(f, sort_keys=True))}</li>")
        if c.get("failures_truncated"):
            extra.append(f"<li class='muted'>… and {_e(c['failures_truncated'])} more</li>")
        for w in c.get("warnings", []):
            extra.append(f"<li><em>warning:</em> {_e(w)}</li>")
        ranges = ", ".join(_rng(r) for r in c.get("ranges", [])) or "—"
        rows.append(
            f"<tr><td><code>{_e(name)}</code></td><td><span class='badge {_e(c['status'])}'>{_e(c['status'])}</span></td>"
            f"<td>{_e(c['detail'])}{'<ul>' + ''.join(extra) + '</ul>' if extra else ''}</td><td>{_e(ranges)}</td></tr>")
    return ("<div class='scroll'><table><thead><tr><th>Check</th><th>Result</th><th>Detail</th>"
            "<th>Seq range(s)</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table></div>")


def _tail_section(result: dict[str, Any]) -> str:
    t = result["unwitnessed_tail"]
    size, count = t["last_witnessed_tree_size"], t["events_in_tail"]
    if size == 0:
        body = ("<strong>No witnessed STH was accepted, so no event is anchored.</strong> "
                "Every event is in the unwitnessed tail.")
    elif count == 0:
        body = (f"The last witnessed STH (tree size {size}, {_e(_ts(t['last_witnessed_timestamp_ns']))}) covers "
                "the whole trace: there is no unwitnessed tail. Events appended after that STH would not be covered.")
    else:
        body = (f"The last witnessed STH covers tree size {size} ({_e(_ts(t['last_witnessed_timestamp_ns']))}). "
                f"<strong>{count} event(s), seq {_e(t['first_tail_seq'])}–{_e(t['last_tail_seq'])}, are in the "
                "unwitnessed tail</strong> (shaded blue below): protected only by their own signatures.")
    return (f"<div class='callout tail'>{body}<br><span class='muted'>{_e(t['note'])}</span></div>")


def _sth_table(result: dict[str, Any]) -> str:
    rows = []
    for s in result["witnessed_sths"]:
        m = s["root_matches_trace"]
        match = "n/a" if m is None else ("<span class='mark ok'>✓ matches</span>" if m else "<span class='mark no'>✗ differs</span>")
        sig = "<span class='mark ok'>✓ valid</span>" if s["valid"] else \
            "<span class='mark no'>✗ " + _e("; ".join(s["problems"])) + "</span>"
        rows.append(f"<tr><td>{_e(s['tree_size'])}</td><td class='mono'>{_e(str(s['witness_id'])[:12])}</td>"
                    f"<td>{sig}</td><td>{match}</td></tr>")
    if not rows:
        return "<p class='muted'>No witnessed STHs were supplied.</p>"
    return ("<table><thead><tr><th>Tree size</th><th>Witness</th><th>Signatures</th><th>Root vs trace</th></tr></thead>"
            "<tbody>" + "".join(rows) + "</tbody></table>")


def _events_table(result: dict[str, Any]) -> str:
    first = result.get("first_broken_seq_range")
    last_size = result["unwitnessed_tail"]["last_witnessed_tree_size"]
    rows = []
    seqs = [e["seq"] for e in result["events"] if isinstance(e["seq"], int)]
    present = bool(first) and any(first[0] <= q <= first[1] for q in seqs)
    # Events that were deleted or truncated have no row of their own: mark the row after the gap.
    after_gap = None
    if first and not present:
        after_gap = next((q for q in seqs if q > first[1]), None)
    for e in result["events"]:
        seq = e["seq"]
        classes = []
        if not e["ok"]:
            classes.append("bad")
        if first and isinstance(seq, int) and (first[0] <= seq <= first[1] or seq == after_gap):
            classes.append("range")
        if e["index"] >= last_size:
            classes.append("tail")
        mark = "<span class='mark ok'>✓ pass</span>" if e["ok"] else "<span class='mark no'>✗ fail</span>"
        pl = e.get("payload", {})
        payload = f"in: {_e(pl.get('input'))}, out: {_e(pl.get('output'))}"
        notes = "; ".join(e["issues"]) if e["issues"] else ""
        rows.append(f"<tr class='{' '.join(classes)}'><td>{_e(seq)}</td><td>{_e(e['name'])}</td>"
                    f"<td class='mono'>{_e(e['session_id'])}</td><td>{mark}</td><td>{payload}</td><td>{_e(notes)}</td></tr>")
    missing = ""
    if first and not present:
        where = ("the highlighted row is the first event after the gap" if after_gap is not None
                 else "they would come after the last event in this trace (truncation)")
        missing = (f"<p><strong>Seq {_e(_rng(first))} is absent from the trace</strong> (deleted or truncated); "
                   f"{where}.</p>")
    return (missing + "<div class='scroll'><table><thead><tr><th>Seq</th><th>Event</th><th>Session</th><th>Result</th>"
            "<th>Payload</th><th>Notes</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table></div>"
            "<p class='muted'>Red rows failed a per-event check. Bold-shaded rows lie in the first broken range. "
            "Blue rows are in the unwitnessed tail. A ✓ means no per-event check failed, not that the event is true.</p>")


def render_html(result: dict[str, Any], title: str = "TraceLock verification report") -> str:
    ok = result["overall"] == "PASS"
    n = result["events_checked"]
    valid_sths = sum(1 for s in result["witnessed_sths"] if s["valid"])
    banner = (f"<div class='banner {'pass' if ok else 'fail'}'>{_e(result['overall'])}"
              f"<small>{n} events checked · {valid_sths} of {len(result['witnessed_sths'])} witnessed STH(s) valid"
              f"{' · all checks passed' if ok else ' · at least one check failed'}</small></div>")
    first = result.get("first_broken_seq_range")
    broken = ""
    if first:
        broken = (f"<div class='callout broken'><strong>First broken seq range: {_e(_rng(first))}.</strong> "
                  "Tampering, deletion or truncation was detected at or around these events. Exact findings "
                  "(signatures, continuity, payloads) name specific events; root and session checks only bound "
                  "where the break lies.</div>")
    not_proven = ("<div class='callout limits'><strong>What this does NOT prove</strong><ul>"
                  + "".join(f"<li>{_e(x)}</li>" for x in NOT_PROVEN) + "</ul></div>")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(title)}</title><style>{CSS}</style></head>
<body><main>
<h1>{_e(title)}</h1>
<p class="sub">Independent check of an exported agent trace against public keys and witnessed tree heads.</p>
{banner}
{broken}
<h2>Checks</h2>
{_checks_table(result)}
<h2>Unwitnessed tail</h2>
{_tail_section(result)}
<h2>Witnessed tree heads</h2>
{_sth_table(result)}
<h2>Events</h2>
{_events_table(result)}
{not_proven}
<footer>Generated from verifier output (version {_e(result.get('verifier_version'))}). Static file: no scripts, no network.</footer>
</main></body></html>
"""


def write_report(result: dict[str, Any], path: str | Path) -> Path:
    p = Path(path)
    p.write_text(render_html(result), encoding="utf-8")
    return p


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Render a TraceLock verifier result as static HTML.")
    ap.add_argument("--result", required=True, help="JSON written by tracelock.verify")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    write_report(json.loads(Path(args.result).read_text()), args.out)
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
