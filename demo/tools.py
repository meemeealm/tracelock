"""The three mock tools shared by both demo agents. No network, no real side effects."""
from __future__ import annotations

import ast
import hashlib
import json
import operator
from typing import Any

FILES = {
    "notes.txt": "Meeting notes: ship the audit report on Friday. Budget is 1200.",
    "todo.md": "- review ledger\n- rotate keys\n- email the auditor",
    "data.csv": "region,sales\nnorth,120\nsouth,80\neast,95",
}

_BIN = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
        ast.Div: operator.truediv, ast.FloorDiv: operator.floordiv, ast.Mod: operator.mod,
        ast.Pow: operator.pow}
_UN = {ast.USub: operator.neg, ast.UAdd: operator.pos}


def _eval(node: ast.AST) -> float | int:
    if isinstance(node, ast.Expression):
        return _eval(node.body)
    if isinstance(node, ast.Constant) and type(node.value) in (int, float):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _BIN:
        left, right = _eval(node.left), _eval(node.right)
        if isinstance(node.op, ast.Pow) and abs(right) > 100:
            raise ValueError("exponent too large")
        return _BIN[type(node.op)](left, right)
    if isinstance(node, ast.UnaryOp) and type(node.op) in _UN:
        return _UN[type(node.op)](_eval(node.operand))
    raise ValueError("unsupported expression")


class Toolbox:
    """Holds the (fake) outbox so tests can see what 'send_email_stub' was asked to do."""

    def __init__(self, files: dict[str, str] | None = None) -> None:
        self.files = dict(FILES if files is None else files)
        self.outbox: list[dict[str, str]] = []

    def read_file(self, path: str) -> str:
        return self.files.get(path, f"error: no such file {path!r}")

    def send_email_stub(self, to: str, subject: str, body: str) -> str:
        self.outbox.append({"to": to, "subject": subject, "body": body})
        mid = hashlib.sha256(f"{to}|{subject}|{body}".encode()).hexdigest()[:12]
        return json.dumps({"status": "queued", "message_id": f"stub-{mid}"})

    def calculator(self, expression: str) -> str:
        try:
            return str(_eval(ast.parse(expression, mode="eval")))
        except (ValueError, SyntaxError, ZeroDivisionError, TypeError, OverflowError) as exc:
            return f"error: {exc}"

    def call(self, name: str, args: dict[str, Any]) -> str:
        fn = {"read_file": self.read_file, "send_email_stub": self.send_email_stub,
              "calculator": self.calculator}.get(name)
        if fn is None:
            return f"error: unknown tool {name!r}"
        try:
            return fn(**args)
        except TypeError as exc:
            return f"error: bad arguments ({exc})"


def _schema(name: str, desc: str, props: dict[str, str]) -> dict[str, Any]:
    return {"type": "function", "function": {
        "name": name, "description": desc,
        "parameters": {"type": "object", "required": list(props),
                       "properties": {k: {"type": "string", "description": v} for k, v in props.items()}},
    }}


TOOL_SCHEMAS = [
    _schema("read_file", "Read a text file by name.", {"path": "file name, e.g. notes.txt"}),
    _schema("send_email_stub", "Queue an email (stub, nothing is sent).",
            {"to": "recipient", "subject": "subject line", "body": "message body"}),
    _schema("calculator", "Evaluate an arithmetic expression.", {"expression": "e.g. 12 * (3 + 4)"}),
]
