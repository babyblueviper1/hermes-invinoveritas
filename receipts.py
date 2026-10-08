"""Pure logic for invinoveritas-receipts (no Hermes imports, so it can be tested on its own).

A receipt is a signed, salted commitment to one approval decision, issued by invinoveritas POST /decision-receipt.
Only the sha256 of the decision context leaves this machine: the command text, description and session key are
hashed locally. invinoveritas signs salted commitments to the question, the options, that context hash and the
choice, and returns the salt to us alone. The salt is stored next to the receipt in the plugin data dir, so the
holder can later open the receipt to anyone; nobody else can recover the choice from the public receipt.
"""
from __future__ import annotations

import hashlib
import json
import os
import urllib.error
import urllib.request

QUESTION = "hermes-agent approval: allow this dangerous tool call?"
OPTIONS = ["approve", "deny"]

# Hermes choice strings -> receipt option. Anything else (timeout, cancelled, notify_failed, escalate) is not a
# decision between approve and deny, so no receipt is issued for it.
_CHOICE_MAP = {
    "smart_approve": "approve", "smart_deny": "deny",
    "once": "approve", "session": "approve", "always": "approve", "approve": "approve",
    "deny": "deny",
}


def canonical(obj) -> bytes:
    """Sorted-key, compact JSON (stable for the string/list values the hook carries)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def context_of(kw: dict, nonce: str) -> dict:
    """The decision context that gets hashed. Hermes already redacts command/description for the smart path.
    `nonce` is 32 random bytes kept only in the local record: without it the hash sent to invinoveritas could be
    reversed by guessing a short command, with it nobody but the holder can open or link the context."""
    return {
        "nonce": nonce,
        "command": kw.get("command") or "",
        "description": kw.get("description") or "",
        "pattern_key": kw.get("pattern_key") or "",
        "pattern_keys": sorted(kw.get("pattern_keys") or []),
        "session_key": kw.get("session_key") or "",
        "surface": kw.get("surface") or "",
        "tool_call_id": kw.get("tool_call_id") or "",
        "turn_id": kw.get("turn_id") or "",
    }


def new_nonce() -> str:
    return os.urandom(32).hex()


def context_sha256(kw: dict, nonce: str) -> str:
    return hashlib.sha256(canonical(context_of(kw, nonce))).hexdigest()


def wanted(kw: dict, scope: str) -> str | None:
    """The receipt option for this hook call, or None when no receipt should be issued."""
    option = _CHOICE_MAP.get(str(kw.get("choice") or ""))
    if option is None:
        return None
    if (scope or "guardian") == "guardian" and kw.get("decided_by") != "aux_llm":
        return None
    return option


def request_body(kw: dict, option: str, nonce: str) -> dict:
    decided_by = kw.get("decided_by") or "human"
    return {
        "question": QUESTION,
        "options": OPTIONS,
        "choice": option,
        "context_sha256": context_sha256(kw, nonce),
        "decider": {"provider": "hermes-agent", "model": "guardian-llm" if decided_by == "aux_llm" else "human",
                    "request_id": kw.get("tool_call_id") or kw.get("turn_id") or ""},
    }


def post_receipt(api_url: str, api_key: str, body: dict, timeout_s: float = 10.0) -> dict:
    """POST /decision-receipt. Returns the parsed response; raises on transport or HTTP errors."""
    req = urllib.request.Request(api_url.rstrip("/") + "/decision-receipt", data=canonical(body), method="POST",
                                 headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}",
                                          "User-Agent": "hermes-invinoveritas/0.2.0"})
    with urllib.request.urlopen(req, timeout=timeout_s) as r:
        return json.loads(r.read().decode("utf-8"))


def record(resp: dict, kw: dict, body: dict, nonce: str) -> dict:
    """What we keep locally: enough to open the receipt later (salt + the hashed context) and to verify it."""
    return {
        "receipt_event_id": ((resp.get("event") or {}).get("id")),
        "event": resp.get("event"),
        "receipt": resp.get("receipt"),
        "salt": (resp.get("reveal") or {}).get("salt"),
        "choice": body["choice"],
        "context": context_of(kw, nonce),
        "context_sha256": body["context_sha256"],
        "decided_by": kw.get("decided_by") or "human",
        "hermes_choice": kw.get("choice"),
        "verify": "POST the event to https://api.babyblueviper.com/verify-proof (free, no auth)",
    }


# ---- turn-end receipts (0.2.0, NousResearch/hermes-agent#16004) ------------------------------------------------
# When a turn stops on iteration exhaustion, commit to the todo ledger as it stood at that moment, so a completion-shaped
# reply over unresolved obligations is provable afterwards without trusting the exhausted model's own summary.
# The ledger is read from the last todo tool result in the turn's conversation (the same JSON the tool returned);
# only a salted hash of it leaves the machine.
TURN_QUESTION = "hermes-agent turn end: was the todo ledger complete when the turn stopped?"
TURN_OPTIONS = ["complete", "incomplete", "no_ledger"]
_OPEN = ("pending", "in_progress")


def ledger_from_history(messages) -> dict | None:
    """The newest todo tool result in the conversation: {"todos": [...], "summary": {...}}, or None."""
    for m in reversed(list(messages or [])):
        if not isinstance(m, dict) or m.get("role") != "tool":
            continue
        c = m.get("content")
        if isinstance(c, list):        # content parts
            c = "".join(p.get("text", "") for p in c if isinstance(p, dict))
        if not isinstance(c, str) or '"todos"' not in c:
            continue
        try:
            d = json.loads(c)
        except (ValueError, TypeError):
            continue
        if isinstance(d, dict) and isinstance(d.get("todos"), list):
            return {"todos": [{"id": str(t.get("id", "")), "content": str(t.get("content", "")),
                               "status": str(t.get("status", ""))} for t in d["todos"] if isinstance(t, dict)],
                    "revision": d.get("revision")}
    return None


def turn_choice(ledger: dict | None) -> str:
    if ledger is None:
        return "no_ledger"
    return "incomplete" if any(t["status"] in _OPEN for t in ledger["todos"]) else "complete"


def turn_wanted(exit_reason: str, turn_scope: str) -> bool:
    """exhausted (default): only turns that stopped on max_iterations_reached; all: every turn; off: never."""
    s = (turn_scope or "exhausted").lower()
    if s == "off":
        return False
    return s == "all" or str(exit_reason or "").startswith("max_iterations_reached")


def turn_context(kw: dict, ledger: dict | None, response_sha256: str, nonce: str) -> dict:
    todos = (ledger or {}).get("todos") or []
    return {
        "nonce": nonce,
        "session_id": kw.get("session_id") or "",
        "turn_id": kw.get("turn_id") or "",
        "turn_exit_reason": str(kw.get("turn_exit_reason") or ""),
        "completed": bool(kw.get("completed")),
        "ledger": ledger,
        "open_obligations": sum(1 for t in todos if t["status"] in _OPEN),
        "total_obligations": len(todos),
        "final_response_sha256": response_sha256,
    }


def turn_request_body(ctx: dict, choice: str) -> dict:
    return {
        "question": TURN_QUESTION,
        "options": TURN_OPTIONS,
        "choice": choice,
        "context_sha256": hashlib.sha256(canonical(ctx)).hexdigest(),
        "decider": {"provider": "hermes-agent", "model": "turn-ledger", "request_id": ctx["turn_id"]},
    }


def response_sha256(text) -> str:
    return hashlib.sha256((text if isinstance(text, str) else json.dumps(text, default=str)).encode("utf-8")).hexdigest()
