"""invinoveritas-receipts: signed, independently checkable receipts for Hermes approval verdicts and, since 0.2.0, for
turns that stop on iteration exhaustion (the todo ledger at that moment, NousResearch/hermes-agent#16004).

Observe-only. The callback never changes the approval outcome: it returns nothing, never raises into Hermes, and
does its network call on a daemon thread so the approval path is never delayed. Without INVINOVERITAS_API_KEY,
Hermes does not load the plugin at all (requires_env).
"""
from __future__ import annotations

import json
import logging
import os
import threading
from collections import OrderedDict

try:
    from . import receipts
except ImportError:  # imported standalone (e.g. a test runner's package setup), not through Hermes's loader
    import importlib.util as _ilu
    _spec = _ilu.spec_from_file_location("invinoveritas_receipts_logic", os.path.join(os.path.dirname(__file__), "receipts.py"))
    receipts = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(receipts)

logger = logging.getLogger(__name__)
_PLUGIN = "invinoveritas-receipts"


def _data_file():
    try:
        from plugins.plugin_storage import plugin_data_dir
        return plugin_data_dir(_PLUGIN) / "receipts.jsonl"
    except Exception:
        return None


def _issue(kw: dict, option: str, api_url: str, timeout_s: float) -> None:
    try:
        key = os.environ.get("INVINOVERITAS_API_KEY", "")
        if not key:
            return
        nonce = receipts.new_nonce()
        body = receipts.request_body(kw, option, nonce)
        resp = receipts.post_receipt(api_url, key, body, timeout_s)
        rec = receipts.record(resp, kw, body, nonce)
        path = _data_file()
        if path is not None:
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        logger.info("invinoveritas receipt %s for %s (%s)", rec.get("receipt_event_id"), option, rec["decided_by"])
    except Exception as exc:          # a failed receipt never affects Hermes
        logger.warning("invinoveritas receipt not issued: %s: %s", type(exc).__name__, exc)


def _issue_turn(kw: dict, cached: dict | None, api_url: str, timeout_s: float) -> None:
    try:
        ledger = (cached or {}).get("ledger")
        choice = receipts.turn_choice(ledger)
        nonce = receipts.new_nonce()
        tctx = receipts.turn_context(kw, ledger, (cached or {}).get("response_sha256", ""), nonce)
        if choice == "incomplete":       # visible locally even without a key or network
            logger.warning("turn %s stopped (%s) with %d of %d todo obligations unresolved", tctx["turn_id"],
                           tctx["turn_exit_reason"], tctx["open_obligations"], tctx["total_obligations"])
        key = os.environ.get("INVINOVERITAS_API_KEY", "")
        if not key:
            return
        body = receipts.turn_request_body(tctx, choice)
        resp = receipts.post_receipt(api_url, key, body, timeout_s)
        rec = {"kind": "turn_end", "receipt_event_id": (resp.get("event") or {}).get("id"), "event": resp.get("event"),
               "receipt": resp.get("receipt"), "salt": (resp.get("reveal") or {}).get("salt"), "choice": choice,
               "context": tctx, "context_sha256": body["context_sha256"],
               "verify": "POST the event to https://api.babyblueviper.com/verify-proof (free, no auth)"}
        path = _data_file()
        if path is not None:
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        logger.info("invinoveritas turn receipt %s: %s (%s)", rec["receipt_event_id"], choice, tctx["turn_exit_reason"])
    except Exception as exc:
        logger.warning("invinoveritas turn receipt not issued: %s: %s", type(exc).__name__, exc)


def register(ctx):
    scope = str(ctx.get_config("scope", default="guardian") or "guardian")
    api_url = str(ctx.get_config("api_url", default="https://api.babyblueviper.com") or "https://api.babyblueviper.com")
    try:
        timeout_s = float(ctx.get_config("timeout_s", default=10.0) or 10.0)
    except (TypeError, ValueError):
        timeout_s = 10.0

    def on_post_approval_response(**kwargs):
        option = receipts.wanted(kwargs, scope)
        if option is None:
            return None
        threading.Thread(target=_issue, args=(dict(kwargs), option, api_url, timeout_s), daemon=True,
                         name="invinoveritas-receipt").start()
        return None

    ctx.register_hook("post_approval_response", on_post_approval_response)

    turn_scope = str(ctx.get_config("turn_scope", default="exhausted") or "exhausted")
    _turns: "OrderedDict[tuple, dict]" = OrderedDict()     # (session_id, turn_id) -> ledger snapshot, bounded
    _lock = threading.Lock()

    def on_post_llm_call(**kwargs):
        if turn_scope.lower() == "off":
            return None
        try:
            snap = {"ledger": receipts.ledger_from_history(kwargs.get("conversation_history")),
                    "response_sha256": receipts.response_sha256(kwargs.get("assistant_response") or "")}
            with _lock:
                _turns[(kwargs.get("session_id"), kwargs.get("turn_id"))] = snap
                while len(_turns) > 64:
                    _turns.popitem(last=False)
        except Exception as exc:
            logger.debug("turn snapshot skipped: %s", exc)
        return None

    def on_session_end(**kwargs):
        try:
            with _lock:
                cached = _turns.pop((kwargs.get("session_id"), kwargs.get("turn_id")), None)
            if not receipts.turn_wanted(kwargs.get("turn_exit_reason"), turn_scope):
                return None
            threading.Thread(target=_issue_turn, args=(dict(kwargs), cached, api_url, timeout_s), daemon=True,
                             name="invinoveritas-turn-receipt").start()
        except Exception as exc:
            logger.debug("turn receipt skipped: %s", exc)
        return None

    ctx.register_hook("post_llm_call", on_post_llm_call)
    ctx.register_hook("on_session_end", on_session_end)
