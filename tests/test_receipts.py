import hashlib
import importlib
import json
import os
import sys
import threading
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(ROOT))
spec = importlib.util.spec_from_file_location("receipts", os.path.join(ROOT, "receipts.py"))
receipts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receipts)

SMART = dict(command="rm -rf /tmp/build", description="recursive delete", pattern_key="rm_rf", pattern_keys=["rm_rf"],
             session_key="cron:nightly", surface="smart", choice="smart_deny", decided_by="aux_llm",
             tool_call_id="call_1", turn_id="t1")


def test_guardian_scope_only_takes_guardian_verdicts():
    assert receipts.wanted(SMART, "guardian") == "deny"
    assert receipts.wanted(dict(SMART, choice="smart_approve"), "guardian") == "approve"
    human = dict(SMART, choice="once", surface="cli", decided_by=None)
    assert receipts.wanted(human, "guardian") is None
    assert receipts.wanted(human, "all") == "approve"


def test_non_decisions_get_no_receipt():
    for c in ("timeout", "cancelled", "notify_failed", "escalate", "", None):
        assert receipts.wanted(dict(SMART, choice=c), "all") is None


def test_command_never_leaves_the_machine():
    n = receipts.new_nonce()
    body = receipts.request_body(SMART, "deny", n)
    wire = receipts.canonical(body).decode()
    for secret in ("rm -rf", "/tmp/build", "recursive delete", "cron:nightly"):
        assert secret not in wire
    assert set(body) == {"question", "options", "choice", "context_sha256", "decider"}
    assert body["choice"] in body["options"]


def test_nonce_makes_the_hash_unguessable_and_reproducible_by_the_holder():
    n1, n2 = receipts.new_nonce(), receipts.new_nonce()
    assert receipts.context_sha256(SMART, n1) != receipts.context_sha256(SMART, n2)
    ctx = receipts.context_of(SMART, n1)
    assert hashlib.sha256(receipts.canonical(ctx)).hexdigest() == receipts.context_sha256(SMART, n1)


def test_record_keeps_what_opens_the_receipt():
    n = receipts.new_nonce()
    body = receipts.request_body(SMART, "deny", n)
    resp = {"event": {"id": "e1"}, "receipt": {"choice_commitment": "c"}, "reveal": {"salt": "s1"}}
    rec = receipts.record(resp, SMART, body, n)
    assert rec["salt"] == "s1" and rec["context"]["nonce"] == n and rec["receipt_event_id"] == "e1"
    assert hashlib.sha256(receipts.canonical(rec["context"])).hexdigest() == rec["context_sha256"]


def _load_plugin(tmp_path, monkeypatch, post):
    pkg = types.ModuleType("ivv_plugin"); pkg.__path__ = [ROOT]
    sys.modules["ivv_plugin"] = pkg
    sys.modules["ivv_plugin.receipts"] = receipts
    spec2 = importlib.util.spec_from_file_location("ivv_plugin.__init__", os.path.join(ROOT, "__init__.py"),
                                                   submodule_search_locations=[ROOT])
    mod = importlib.util.module_from_spec(spec2); mod.__package__ = "ivv_plugin"; spec2.loader.exec_module(mod)
    monkeypatch.setattr(receipts, "post_receipt", post)
    out = tmp_path / "receipts.jsonl"
    monkeypatch.setattr(mod, "_data_file", lambda: out)
    hooks = {}
    ctx = types.SimpleNamespace(get_config=lambda k, default=None: default,
                                register_hook=lambda name, fn: hooks.setdefault(name, fn))
    mod.register(ctx)
    return hooks, out


def _join():
    for t in threading.enumerate():
        if t.name == "invinoveritas-receipt":
            t.join(5)


def test_hook_issues_a_receipt_off_the_approval_path(tmp_path, monkeypatch):
    monkeypatch.setenv("INVINOVERITAS_API_KEY", "ivv_test")
    sent = []
    hooks, out = _load_plugin(tmp_path, monkeypatch, lambda url, key, body, t: sent.append(body) or
                              {"event": {"id": "ev"}, "receipt": {}, "reveal": {"salt": "ss"}})
    assert hooks["post_approval_response"](**SMART) is None
    _join()
    assert len(sent) == 1 and sent[0]["choice"] == "deny"
    rec = json.loads(out.read_text().strip())
    assert rec["receipt_event_id"] == "ev" and rec["salt"] == "ss"


def test_a_failing_api_never_reaches_hermes(tmp_path, monkeypatch):
    monkeypatch.setenv("INVINOVERITAS_API_KEY", "ivv_test")
    def boom(*a, **k):
        raise OSError("network down")
    hooks, out = _load_plugin(tmp_path, monkeypatch, boom)
    assert hooks["post_approval_response"](**SMART) is None
    _join()
    assert not out.exists()


def test_human_decisions_are_skipped_in_guardian_scope(tmp_path, monkeypatch):
    monkeypatch.setenv("INVINOVERITAS_API_KEY", "ivv_test")
    sent = []
    hooks, _ = _load_plugin(tmp_path, monkeypatch, lambda *a: sent.append(a) or {})
    hooks["post_approval_response"](**dict(SMART, choice="once", decided_by=None, surface="cli"))
    _join()
    assert sent == []
