"""invinoveritas-receipts: a signed, independently checkable receipt for each Hermes approval verdict.

Observe-only. The callback never changes the approval outcome: it returns nothing, never raises into Hermes, and
does its network call on a daemon thread so the approval path is never delayed. Without INVINOVERITAS_API_KEY,
Hermes does not load the plugin at all (requires_env).
"""
from __future__ import annotations

import json
import logging
import os
import threading

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
