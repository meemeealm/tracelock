"""Tool-calling agent on Groq or OpenAI (same OpenAI-compatible client). Needs network + a key.

Provider is chosen with --provider {groq,openai} (or LLM_PROVIDER in .env; default groq):
  groq    GROQ_API_KEY,   GROQ_MODEL            (endpoint fixed to Groq's OpenAI-compatible URL)
  openai  OPENAI_API_KEY, OPENAI_MODEL, optional OPENAI_BASE_URL (proxies / compatible servers)
Model names change often: verify them against the provider's current docs.

Instrumentation: manual gen_ai.* spans. The task suggests trying the OpenTelemetry
OpenAI instrumentation package first; it is not in the pinned dependency list and
could not be tested offline, so this file takes the specified fallback (manual spans).

Usage:  python -m demo.agent_groq [--provider openai] --task "..." [--record [NAME]]
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from .tools import TOOL_SCHEMAS, Toolbox

GROQ_BASE_URL = "https://api.groq.com/openai/v1"
FIXTURE_DIR = Path(__file__).parent / "fixtures"
PROVIDERS: dict[str, dict[str, str | None]] = {
    "groq": {"base_url": GROQ_BASE_URL, "base_url_env": None,
             "key_env": "GROQ_API_KEY", "model_env": "GROQ_MODEL"},
    "openai": {"base_url": None, "base_url_env": "OPENAI_BASE_URL",  # None = the SDK default endpoint
               "key_env": "OPENAI_API_KEY", "model_env": "OPENAI_MODEL"},
}
SYSTEM_PROMPT = "You are a careful assistant. Use the tools when helpful, then answer briefly."


class ConfigError(ValueError):
    """Missing or invalid provider configuration."""


@dataclass(frozen=True)
class ProviderConfig:
    name: str
    base_url: str | None
    api_key: str = ""  # never printed or logged
    model: str = ""

    def __repr__(self) -> str:  # keep the key out of tracebacks and logs
        return f"ProviderConfig(name={self.name!r}, base_url={self.base_url!r}, model={self.model!r})"


def resolve_provider(name: str, env: Mapping[str, str]) -> ProviderConfig:
    """Read the provider's settings from ``env``; raise ConfigError listing what is missing."""
    if name not in PROVIDERS:
        raise ConfigError(f"unknown provider {name!r}; choose from {sorted(PROVIDERS)}")
    spec = PROVIDERS[name]
    missing = [spec[k] for k in ("key_env", "model_env") if not env.get(spec[k] or "")]
    if missing:
        raise ConfigError(f"set {', '.join(missing)} in .env (see .env.example) for provider {name!r}")
    base_url = (env.get(spec["base_url_env"] or "") or spec["base_url"]) or None
    return ProviderConfig(name, base_url, env[spec["key_env"]], env[spec["model_env"]])


def is_retryable(exc: Exception) -> bool:
    """429 and 5xx responses, plus connection/timeout errors, are retried."""
    status = getattr(exc, "status_code", None)
    if isinstance(status, int):
        return status == 429 or status >= 500
    return type(exc).__name__ in {"APIConnectionError", "APITimeoutError"}


def call_with_backoff(
    fn: Callable[[], Any],
    max_retries: int = 5,
    base_delay: float = 1.0,
    sleep: Callable[[float], None] = time.sleep,
    jitter: Callable[[], float] = random.random,
) -> Any:
    """Call ``fn``; on a retryable error wait base*2^attempt (+ jitter) and try again."""
    for attempt in range(max_retries + 1):
        try:
            return fn()
        except Exception as exc:
            if attempt == max_retries or not is_retryable(exc):
                raise
            sleep(base_delay * (2 ** attempt) + jitter() * 0.1)
    raise AssertionError("unreachable")


def run_agent(
    client: Any,
    model: str,
    task: str,
    tracer: Any,
    max_steps: int = 10,
    sleep: Callable[[float], None] = time.sleep,
    toolbox: Toolbox | None = None,
) -> str:
    """Tool-calling loop (max ``max_steps`` model calls). Emits gen_ai.* spans."""
    tools = toolbox or Toolbox()
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": task},
    ]
    answer = "(stopped: max steps reached)"
    with tracer.start_as_current_span("invoke_agent") as root:
        root.set_attribute("gen_ai.operation.name", "invoke_agent")
        root.set_attribute("gen_ai.request.model", model)
        for _ in range(max_steps):
            prompt = json.dumps(messages)
            with tracer.start_as_current_span(f"chat {model}") as chat:
                chat.set_attribute("gen_ai.operation.name", "chat")
                chat.set_attribute("gen_ai.request.model", model)
                chat.set_attribute("gen_ai.input.messages", prompt)
                resp = call_with_backoff(
                    lambda: client.chat.completions.create(
                        model=model, messages=messages, tools=TOOL_SCHEMAS),
                    sleep=sleep)
                msg = resp.choices[0].message
                calls = list(getattr(msg, "tool_calls", None) or [])
                usage = getattr(resp, "usage", None)
                if usage is not None and getattr(usage, "prompt_tokens", None) is not None:
                    chat.set_attribute("gen_ai.usage.input_tokens", int(usage.prompt_tokens))
                    chat.set_attribute("gen_ai.usage.output_tokens", int(usage.completion_tokens))
                chat.set_attribute("gen_ai.output.messages", json.dumps({
                    "content": msg.content,
                    "tool_calls": [{"id": c.id, "name": c.function.name,
                                    "arguments": c.function.arguments} for c in calls]}))
            if not calls:
                answer = msg.content or ""
                break
            messages.append({
                "role": "assistant", "content": msg.content,
                "tool_calls": [{"id": c.id, "type": "function",
                                "function": {"name": c.function.name, "arguments": c.function.arguments}}
                               for c in calls]})
            for c in calls:
                with tracer.start_as_current_span(f"execute_tool {c.function.name}") as ts:
                    ts.set_attribute("gen_ai.operation.name", "execute_tool")
                    ts.set_attribute("gen_ai.tool.name", c.function.name)
                    ts.set_attribute("gen_ai.tool.call.id", c.id)
                    ts.set_attribute("gen_ai.tool.call.arguments", c.function.arguments or "")
                    try:
                        args = json.loads(c.function.arguments or "{}")
                        result = tools.call(c.function.name, args) if isinstance(args, dict) \
                            else "error: arguments must be a JSON object"
                    except ValueError:
                        result = "error: invalid JSON arguments"
                    ts.set_attribute("gen_ai.tool.call.result", result)
                messages.append({"role": "tool", "tool_call_id": c.id, "content": result})
    return answer


def main(argv: list[str] | None = None, env: Mapping[str, str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="TraceLock demo agent on Groq or OpenAI")
    ap.add_argument("--provider", choices=sorted(PROVIDERS), help="default: LLM_PROVIDER from .env, else groq")
    ap.add_argument("--task", default="Read notes.txt, compute 12*(3+4), and email the result to auditor@example.com.")
    ap.add_argument("--out-dir", help="default: out/<provider>")
    ap.add_argument("--record", nargs="?", const="", metavar="NAME",
                    help="also save the spans as demo/fixtures/NAME (default <provider>_session.json)")
    args = ap.parse_args(argv)

    if env is None:  # real run: read .env, then the process environment
        try:
            from dotenv import load_dotenv
            load_dotenv()
        except ImportError:
            pass
        env = os.environ
    try:
        cfg = resolve_provider(args.provider or env.get("LLM_PROVIDER") or "groq", env)
    except ConfigError as exc:
        print(exc, file=sys.stderr)
        return 2

    from openai import OpenAI
    from .agent_scripted import produce_artifacts
    from .fixtures_io import RecordingProcessor, save_fixture
    from tracelock.verify import verify_files

    client = OpenAI(api_key=cfg.api_key, **({"base_url": cfg.base_url} if cfg.base_url else {}))
    recorder = RecordingProcessor()
    out_dir = args.out_dir or f"out/{cfg.name}"
    art = produce_artifacts(
        out_dir, session_id=f"{cfg.name}-session",
        session_fn=lambda tracer: print(run_agent(client, cfg.model, args.task, tracer)),
        extra_processors=(recorder,))
    if args.record is not None:
        FIXTURE_DIR.mkdir(exist_ok=True)
        name = args.record or f"{cfg.name}_session.json"
        save_fixture(FIXTURE_DIR / name, recorder.records, note=f"recorded from {cfg.name} model {cfg.model}")
        print(f"fixture saved: {FIXTURE_DIR / name}")
    result = verify_files(**art.verify_args())
    print(f"verifier: {result['overall']} ({art.n_events} events) -> artifacts in {art.out_dir}")
    return 0 if result["overall"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
