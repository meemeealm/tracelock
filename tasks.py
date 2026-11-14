#!/usr/bin/env python3
"""Cross-platform replacement for the Makefile. Needs only Python.

    python tasks.py                 # list commands
    python tasks.py install         # pip install -r requirements.txt
    python tasks.py test            # pytest -q
    python tasks.py demo            # witness process + scripted agent + verifier + HTML report
    python tasks.py attacks         # the six tamper scenarios as a markdown table
    python tasks.py bench           # overhead microbenchmark
    python tasks.py groq            # LLM demo on Groq   (needs network, GROQ_API_KEY, GROQ_MODEL in .env)
    python tasks.py openai          # LLM demo on OpenAI (needs network, OPENAI_API_KEY, OPENAI_MODEL in .env)
    python tasks.py all             # test, then demo, then attacks
    python tasks.py clean           # remove out/, caches

Extra arguments are passed through to the underlying command, e.g.
    python tasks.py demo --seed 7 --sth-interval 3
    python tasks.py test -k merkle
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PY = sys.executable

COMMANDS: dict[str, tuple[list[str], str]] = {
    "install": ([PY, "-m", "pip", "install", "-r", "requirements.txt"], "install pinned dependencies"),
    "test": ([PY, "-m", "pytest", "-q"], "run the test suite"),
    "demo": ([PY, "-m", "demo.run_all"], "witness + scripted agent + verifier + HTML report (out/run_all/)"),
    "attacks": ([PY, "-m", "attacks.tamper"], "run the six tamper scenarios"),
    "bench": ([PY, "-m", "bench.overhead"], "overhead microbenchmark"),
    "groq": ([PY, "-m", "demo.agent_groq", "--provider", "groq", "--record"], "Groq demo (network + API key required)"),
    "openai": ([PY, "-m", "demo.agent_groq", "--provider", "openai", "--record"], "OpenAI demo (network + API key required)"),
}


def run(cmd: list[str]) -> int:
    print("$ " + " ".join(cmd), flush=True)
    return subprocess.call(cmd, cwd=ROOT)


def clean() -> int:
    shutil.rmtree(ROOT / "out", ignore_errors=True)
    shutil.rmtree(ROOT / ".pytest_cache", ignore_errors=True)
    for p in ROOT.rglob("__pycache__"):
        shutil.rmtree(p, ignore_errors=True)
    print("cleaned out/, .pytest_cache and __pycache__")
    return 0


def usage() -> int:
    print(__doc__)
    return 0


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help", "help"):
        return usage()
    name, extra = argv[0], argv[1:]
    if name == "clean":
        return clean()
    if name == "all":
        for step in ("test", "demo", "attacks"):
            code = run(COMMANDS[step][0])
            if code != 0:
                print(f"stopped: '{step}' failed with exit code {code}")
                return code
        return 0
    if name not in COMMANDS:
        print(f"unknown command {name!r}\n")
        usage()
        return 2
    return run(COMMANDS[name][0] + extra)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
