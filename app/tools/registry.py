"""Registry of SAFE, SIMULATED tools that the LLM may *propose* to call.

None of these tools touch the real system:

* ``calculator``        - evaluates arithmetic with a whitelisting AST walker (no ``eval``)
* ``search_demo``       - returns canned search results (treated as EXTERNAL_CONTENT)
* ``read_demo_file``    - reads from an in-memory dictionary, never the disk
* ``send_demo_message`` - appends to an in-memory outbox; nothing is sent anywhere

Each tool declares its *permission class* and whether it is *sensitive*. The
tool firewall (``authorization.py``) uses these declarations to decide whether
a proposed call may run.
"""

from __future__ import annotations

import ast
import operator
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

from app.config import DEMO_CANARY


class Permission(str, Enum):
    COMPUTE = "COMPUTE"                # pure computation, no data access
    READ_PUBLIC = "READ_PUBLIC"        # reads public / external data
    READ_INTERNAL = "READ_INTERNAL"    # reads application files
    SEND_EXTERNAL = "SEND_EXTERNAL"    # sends data out of the application


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    permission: Permission
    sensitive: bool
    params: dict[str, type]
    required: tuple[str, ...]
    handler: Callable[[dict[str, Any]], str]
    max_arg_chars: int = 500


# ---------------------------------------------------------------------------
# Demo data (fake, safe)
# ---------------------------------------------------------------------------
DEMO_FILES: dict[str, str] = {
    "public_report.txt": "PromptGuard public report: 1,204 requests scanned this week, 87 attacks blocked.",
    "meeting_notes.txt": "Team meeting notes: ship the dashboard on Friday; review tool-firewall tests.",
    "internal_config.txt": f"INTERNAL - protected configuration. deployment_key={DEMO_CANARY}",
}
PROTECTED_FILES = {"internal_config.txt"}

SEARCH_RESULTS: dict[str, str] = {
    "prompt injection": "OWASP LLM01: Prompt injection manipulates an LLM through crafted inputs.",
    "encryption": "Symmetric encryption uses one shared key; asymmetric uses a public/private key pair.",
    "weather": "Weather today: sunny, 24C. (Demo search result.)",
}


# ---------------------------------------------------------------------------
# Safe calculator - an AST whitelist instead of eval()
# ---------------------------------------------------------------------------
_BIN_OPS: dict[type, Callable[[Any, Any], Any]] = {
    ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
    ast.Div: operator.truediv, ast.FloorDiv: operator.floordiv, ast.Mod: operator.mod, ast.Pow: operator.pow,
}
_UNARY_OPS: dict[type, Callable[[Any], Any]] = {ast.UAdd: operator.pos, ast.USub: operator.neg}


def safe_calculate(expression: str) -> float | int:
    """Evaluate +, -, *, /, //, %, ** on numbers only. Anything else is rejected."""
    if len(expression) > 100:
        raise ValueError("Expression too long")
    tree = ast.parse(expression, mode="eval")

    def ev(node: ast.AST) -> float | int:
        if isinstance(node, ast.Expression):
            return ev(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
            return node.value
        if isinstance(node, ast.BinOp) and type(node.op) in _BIN_OPS:
            left, right = ev(node.left), ev(node.right)
            if isinstance(node.op, ast.Pow) and (abs(right) > 10 or abs(left) > 1_000_000):
                raise ValueError("Exponent too large")
            return _BIN_OPS[type(node.op)](left, right)
        if isinstance(node, ast.UnaryOp) and type(node.op) in _UNARY_OPS:
            return _UNARY_OPS[type(node.op)](ev(node.operand))
        raise ValueError(f"Unsupported expression element: {type(node).__name__}")

    return ev(tree)


class ToolRegistry:
    """Holds tool specifications and the simulated side effects (outbox)."""

    def __init__(self) -> None:
        self.outbox: list[dict[str, str]] = []
        self.tools: dict[str, ToolSpec] = {}
        for spec in self._build_specs():
            self.tools[spec.name] = spec

    def _build_specs(self) -> list[ToolSpec]:
        return [
            ToolSpec("calculator", "Evaluate an arithmetic expression.", Permission.COMPUTE, False,
                     {"expression": str}, ("expression",), self._calculator, max_arg_chars=100),
            ToolSpec("search_demo", "Search a small canned knowledge base.", Permission.READ_PUBLIC, False,
                     {"query": str}, ("query",), self._search),
            ToolSpec("read_demo_file", "Read a file from the demo file store.", Permission.READ_INTERNAL, True,
                     {"filename": str}, ("filename",), self._read_file, max_arg_chars=64),
            ToolSpec("send_demo_message", "Send a message (simulated outbox only).", Permission.SEND_EXTERNAL, True,
                     {"recipient": str, "message": str}, ("recipient", "message"), self._send_message, max_arg_chars=1000),
        ]

    def get(self, name: str) -> ToolSpec | None:
        return self.tools.get(name)

    # ---------------------------------------------------------- handlers
    @staticmethod
    def _calculator(args: dict[str, Any]) -> str:
        return f"{args['expression']} = {safe_calculate(args['expression'])}"

    @staticmethod
    def _search(args: dict[str, Any]) -> str:
        query = args["query"].lower()
        hits = [text for key, text in SEARCH_RESULTS.items() if key in query]
        return " | ".join(hits) if hits else f"No demo results for '{args['query']}'."

    @staticmethod
    def _read_file(args: dict[str, Any]) -> str:
        return DEMO_FILES[args["filename"]]

    def _send_message(self, args: dict[str, Any]) -> str:
        self.outbox.append({"recipient": args["recipient"], "message": args["message"]})
        return f"(simulated) Message queued for {args['recipient']}. Nothing was actually sent."

    def describe(self) -> list[dict[str, Any]]:
        return [
            {"name": t.name, "description": t.description, "permission": t.permission.value,
             "sensitive": t.sensitive, "params": list(t.params), "required": list(t.required)}
            for t in self.tools.values()
        ]
