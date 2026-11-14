"""One-command demo: witness (separate OS process) + scripted agent + verifier + HTML report.

    python -m demo.run_all [--out-dir out/run_all] [--seed 1234] [--sth-interval 5]

Outputs in the out dir: trace.jsonl, witnessed_sths.json, verification.json, report.html,
plus keys/, ledger.db and witness_data/ (the witness's own directory and key).
Exit code 0 = the verifier returned PASS.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

from tracelock.report import write_report
from tracelock.signing import generate_private_key, save_private_key, save_public_key
from tracelock.verify import verify_files

from .agent_scripted import DEFAULT_SEED, produce_artifacts

REPO_ROOT = Path(__file__).resolve().parent.parent
MARKER = ".tracelock-demo"


def _prepare(out: Path) -> None:
    """Start from an empty directory; refuse to wipe a directory we did not create."""
    if out.exists() and any(out.iterdir()):
        if not (out / MARKER).exists():
            raise SystemExit(f"refusing to overwrite {out}: not a TraceLock demo directory")
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)
    (out / MARKER).write_text("created by demo.run_all\n")


def start_witness(data_dir: Path, log_pubkey: Path) -> tuple[subprocess.Popen, str]:
    """Launch the witness as its own process (own key, own data dir). Returns (proc, url)."""
    proc = subprocess.Popen(
        [sys.executable, "-u", "-m", "tracelock.witness", "serve", "--data-dir", str(data_dir),
         "--log-pubkey", str(log_pubkey), "--port", "0"],
        cwd=REPO_ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    line = proc.stdout.readline()
    m = re.search(r"listening on (http://\S+)", line)
    if not m:
        proc.kill()
        raise SystemExit(f"witness failed to start: {line!r}")
    return proc, m.group(1)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="TraceLock end-to-end demo")
    ap.add_argument("--out-dir", default="out/run_all")
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED)
    ap.add_argument("--sth-interval", type=int, default=5)
    args = ap.parse_args(argv)
    out = Path(args.out_dir)
    _prepare(out)

    # Keys first: the witness must know the log's public key before it starts.
    keys = out / "keys"
    keys.mkdir()
    for name in ("log", "agent"):
        k = generate_private_key()
        save_private_key(k, keys / f"{name}.key")
        save_public_key(k.public_key(), keys / f"{name}.pub")

    witness_dir = out / "witness_data"
    proc, url = start_witness(witness_dir, keys / "log.pub")
    print(f"[1/4] witness process started (pid {proc.pid}) at {url}, data dir {witness_dir}")
    try:
        art = produce_artifacts(out, seed=args.seed, sth_interval=args.sth_interval,
                                witness_url=url, witness_dir=witness_dir)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    print(f"[2/4] scripted agent ran (seed {args.seed}): {art.n_events} events in the ledger"
          + (f"; WITNESS ERRORS: {art.hook_errors}" if art.hook_errors else ""))

    result = verify_files(**art.verify_args())
    (out / "verification.json").write_text(json.dumps(result, indent=1))
    print(f"[3/4] verifier: {result['overall']}")
    for name, c in result["checks"].items():
        print(f"        {c['status']:4} {name}: {c['detail']}")
    report = write_report(result, out / "report.html")
    print(f"[4/4] report written: {report}")
    tail = result["unwitnessed_tail"]
    print(f"unwitnessed tail: {tail['events_in_tail']} event(s) after tree size {tail['last_witnessed_tree_size']}")
    return 0 if result["overall"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
